package scalaz.stream.ssl

import javax.net.ssl.{SSLParameters, SSLContext, SSLEngine}

trait SSLConfig {

  def createEngine: SSLEngine
  def usingContext(context: SSLContext): SSLConfig 
  def withParameters(params: SSLParameters): SSLConfig

}

object SSLConfig {

  val client: SSLConfig = new SSLConfigImpl(true, None, SSLContext.getDefault) 

  val server: SSLConfig = new SSLConfigImpl(false, None, SSLContext.getDefault)

}

private[ssl] class SSLConfigImpl(client: Boolean, params: Option[SSLParameters], context: SSLContext) extends SSLConfig {

  def createEngine: SSLEngine = {
    val engine = context.createSSLEngine
    engine.setSSLParameters(params.getOrElse(context.getDefaultSSLParameters))
    engine.setUseClientMode(client)
    engine
  }

  def usingContext(newContext: SSLContext): SSLConfig = 
    new SSLConfigImpl(client, params, newContext)

  def withParameters(newParams: SSLParameters): SSLConfig =
    new SSLConfigImpl(client, Some(newParams), context)

}
