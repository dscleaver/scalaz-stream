package scalaz.stream

import Process._
import org.scalacheck.Prop._
import org.scalacheck.Properties
import javax.net.ssl._
import java.security._
import java.io._
import processes._
import scalaz.stream.ssl.SSLConfig
import scalaz.concurrent.Task
import scalaz.{\/, -\/, \/-}
import scala.util.Random
import scala.concurrent.SyncVar
import scalaz.stream.Process.Halt
import scalaz.stream.ReceiveY.HaltL
import scalaz.stream.ReceiveY.HaltR
import scalaz.stream.ReceiveY.ReceiveL
import scalaz.stream.ReceiveY.ReceiveR

object SslClientServer {

  def withSsl: (Exchange[Bytes, Bytes], Exchange[Bytes, Bytes]) = {
    val loop1 = Exchange.loopBack(id[Bytes])
    val loop2 = Exchange.loopBack(id[Bytes])

    val makeClientServer = loop1.zip(loop2).map {
      case (loop1, loop2) =>
        val client = ssl.ssl(SSLConfig.client.usingContext(context))(Exchange(loop1.read, loop2.write))
        val server = ssl.ssl(SSLConfig.server.usingContext(context))(Exchange(loop2.read, loop1.write))

        (client, server)
    }
    makeClientServer.runLast.run.get
  }

  val keyStore = {
    val ks = KeyStore.getInstance("JKS")
    val fis = getClass.getClassLoader.getResourceAsStream("keystore.jks")
    ks.load(fis, "password".toCharArray())
    ks
  }

  val keyManagerFactory = {
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory
            .getDefaultAlgorithm());
    kmf.init(keyStore, "password".toCharArray())    
    kmf
  }

  val trustManager = new X509TrustManager() {
    def getAcceptedIssuers: Array[java.security.cert.X509Certificate] = {
      return null;
    }

    def checkClientTrusted(certs: Array[java.security.cert.X509Certificate], authType: String) = {}

    def checkServerTrusted(certs: Array[java.security.cert.X509Certificate], authType: String) {}
  }

  val context = {
    val c = SSLContext.getInstance("TLS")
    c.init(keyManagerFactory.getKeyManagers, Array(trustManager), null)
    c     
  } 
}

object SslServer {

  def echoAll: Writer1[Bytes, Bytes, Bytes] =
    receive1[Bytes, Bytes \/ Bytes]({
      i => emitSeq(Seq(\/-(i), -\/(i))) fby echoAll
    })

  def echo(ex: Exchange[Bytes, Bytes]): Process[Task, Bytes] =
    ex.readThrough(echoAll).runReceive

}

object SslClient {

  def echo(ex: Exchange[Bytes, Bytes], data: Bytes): Process[Task, Bytes] = {

    def echoSent: WyeW[Bytes, Bytes, Bytes, Bytes] = {
      def go(collected: Int): WyeW[Bytes, Bytes, Bytes, Bytes] = {
        receiveBoth {
          case ReceiveL(rcvd) =>
            emitO(rcvd) fby
              (if (collected + rcvd.size >= data.size) halt
              else go(collected + rcvd.size))
          case ReceiveR(data) => tell(data) fby go(collected)
          case HaltL(rsn)     => Halt(rsn)
          case HaltR(_)       => go(collected)
        }
      }

      go(0)
    }


    ex.wye(echoSent).run(emit(data))
  }

}

object SslSpec extends Properties("ssl") {

  property("handshake-echo-done") = secure {
    val size: Int = 500000
    val array1 = Array.fill[Byte](size)(1)
    Random.nextBytes(array1)

    val stop = async.signal[Boolean]
    stop.set(false).run

    val (client, server) = SslClientServer.withSsl

    val serverGot = new SyncVar[Throwable \/ IndexedSeq[Byte]]
    stop.discrete.wye(SslServer.echo(server))(wye.interrupt).runLog.map(_.map(_.toSeq).flatten).runAsync(serverGot.put)

    val clientGot =
        SslClient.echo(client, Bytes.of(array1)).runLog.run.map(_.toSeq).flatten
      stop.set(true).run

      (serverGot.get(30000) == Some(\/-(clientGot))) :| s"Server and client got same data" &&
        (clientGot == array1.toSeq) :| "client got same bytes it sent"
     
  }

}

