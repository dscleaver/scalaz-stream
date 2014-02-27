package scalaz.stream

import java.nio.ByteBuffer
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLEngineResult.HandshakeStatus._
import javax.net.ssl.SSLEngineResult.Status._
import scalaz.\/
import scalaz.stream.Process._
import scalaz.stream.processes._

package object ssl {

  def ssl(config: SSLConfig = SSLConfig.client)(e: Exchange[Bytes, Bytes]): Exchange[Bytes, Bytes] = {
    val engine = config.createEngine  

    def addCapacity(b: ByteBuffer, size: Int): ByteBuffer = {
      val newB = ByteBuffer.allocate(b.position + size)
      b.flip()
      newB.put(b)
      newB
    }

    def perform[T[_]](op: (ByteBuffer, ByteBuffer) => SSLEngineResult, bufferSize: Int, more: Process[T, Bytes])(bytes: Bytes): Process[T, (Bytes, Option[Bytes])] = {
      def doOp(outBuffer: ByteBuffer): Process[T, (Bytes, Option[Bytes])] = {
        val result = op(bytes.asByteBuffer, outBuffer)
        result.getStatus match {
          case BUFFER_OVERFLOW =>
            doOp(addCapacity(outBuffer, bufferSize))
          case BUFFER_UNDERFLOW =>
            more.flatMap(b => perform(op, bufferSize, more)(bytes ++ b))
          case OK if result.bytesProduced > 0 =>
            outBuffer.flip()
            emit((bytes drop result.bytesConsumed, Some(Bytes of outBuffer)))
          case OK =>
            emit((bytes drop result.bytesConsumed, None))
          case CLOSED => 
            halt
        }
      }
      doOp(ByteBuffer.allocate(bufferSize))
    }

    val performUnwrap: (ByteBuffer, ByteBuffer) => SSLEngineResult = (src, dst) => {
      val writeableBuffer = ByteBuffer.allocate(src.capacity)
      writeableBuffer.put(src)
      writeableBuffer.flip()
      engine.unwrap(writeableBuffer, dst)
    }

    val wrap = perform(engine.wrap(_,_), engine.getSession.getPacketBufferSize, await1[Bytes])(_)
    val unwrap = perform(performUnwrap(_,_), engine.getSession.getApplicationBufferSize, await1[Bytes])(_)

    val unwrapL = perform(performUnwrap(_,_), engine.getSession.getApplicationBufferSize, awaitL[Bytes])(_)
    val wrapL = perform(engine.wrap(_,_), engine.getSession.getPacketBufferSize, awaitL[Bytes])(_)

    def handshake(incomingBytes: Bytes): Wye[Bytes, Bytes, Bytes \/ Bytes] = engine.getHandshakeStatus match {
      case NEED_UNWRAP if !incomingBytes.isEmpty =>
        unwrapL(incomingBytes).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Nothing, Bytes]](halt)(emitO(_)) fby handshake(remaining)
        }
      case NEED_UNWRAP => 
        awaitL[Bytes].flatMap(b => unwrapL(b)).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Nothing, Bytes]](halt)(emitO(_)) fby handshake(remaining)
        }
      case NEED_TASK =>
        engine.getDelegatedTask.run
        handshake(incomingBytes)
      case NEED_WRAP =>
        wrapL(Bytes.empty).flatMap {
          case (_, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Bytes, Nothing]](halt)(emitW(_)) fby handshake(incomingBytes)
        }
      case NOT_HANDSHAKING =>
        sendAndReceive(incomingBytes, Bytes.empty)
    }

    def receive(incomingBytes: Bytes): Writer1[Bytes, Bytes, Bytes] = engine.getHandshakeStatus match {
      case NEED_TASK => 
        engine.getDelegatedTask().run()
        receive(incomingBytes)
      case NEED_WRAP =>
        wrap(Bytes.empty).flatMap {
          case (_, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Bytes, Nothing]](halt)(emitW(_)) fby receive(incomingBytes)
        }
      case _ if !incomingBytes.isEmpty =>
        unwrap(incomingBytes).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Nothing, Bytes]](halt)(emitO(_)) fby receive(remaining)
        }
      case _ => 
        await1[Bytes].flatMap(unwrap(_)).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Nothing, Bytes]](halt)(emitO(_)) fby receive(remaining)
        }
    }
    
    def send(outgoingBytes: Bytes): Writer1[Bytes, Bytes, Bytes] = 
      if(outgoingBytes.isEmpty)
        await1[Bytes].flatMap(wrap(_)).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Bytes, Nothing]](halt)(emitW(_)) fby send(remaining)
        }
      else
        wrap(outgoingBytes).flatMap {
          case (remaining, possibleOutput) =>
            possibleOutput.fold[Writer[Nothing, Bytes, Nothing]](halt)(emitW(_)) fby send(remaining)
        }
        
        

    def sendAndReceive(incomingBytes: Bytes, outgoingBytes: Bytes): WyeW[Bytes, Bytes, Bytes, Bytes] = wye.merge[Bytes \/ Bytes].attachL(receive(incomingBytes)).attachR(send(outgoingBytes))
     
    engine.beginHandshake()
    
    e.wye(handshake(Bytes.empty))

  }


}
