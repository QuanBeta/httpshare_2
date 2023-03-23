package me.aisuneko.httpshare

import android.content.Context
import android.net.Uri
import android.util.Log
import me.aisuneko.httpshare.a.NanoHTTPD
import me.aisuneko.httpshare.a.NoSSLv3SocketFactory
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.*


private const val HOST = "0.0.0.0"
private const val PORT = 6789

class Server(uri: Uri, name: String, var context: Context) : NanoHTTPD(HOST, PORT) {
    private var inputStream: InputStream? = null
    private var mime: String? = null
    private var applicationContext = context
    private var link = uri
    private var fileName = name

    //    private val timestamp =
//        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-kkmmss"))
    private var tempFile: File? = null

    //    private val name = link.lastPathSegment
    override fun serve(session: IHTTPSession?): Response {
        return Response(Response.Status.OK, mime, FileInputStream(tempFile))
    }

    override fun start() {
        val inputStream2: InputStream = context.assets.open("mycert.crt")
            val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
            val certificate: X509Certificate = certificateFactory.generateCertificate(inputStream2) as X509Certificate

            // Create a keystore and store the certificate in it
            val keyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(context.resources.openRawResource(R.raw.keystore), "123456".toCharArray())
            keyStore.setCertificateEntry("mycert", certificate)

            // Create a KeyManagerFactory and initialize it with the keystore
            val keyManagerFactory: KeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore,  "123456".toCharArray())

            // Create an SSLContext and initialize it with the KeyManagerFactory
            val sslContext: SSLContext = SSLContext.getInstance("TLS")
            sslContext.init(keyManagerFactory.keyManagers, null, null)

            // Create a ServerSocketFactory using the SSLContext
        makeSecure(sslContext.serverSocketFactory, arrayOf(sslContext.protocol))
        super.start()
        inputStream = applicationContext.contentResolver.openInputStream(link)

        mime = applicationContext.contentResolver.getType(link)
        Log.e(javaClass.simpleName, "start:: $mime")
        if (tempFile?.exists() == true) {
            tempFile?.delete()
        }
        tempFile = File.createTempFile("klkk", "httpshare", applicationContext.cacheDir)
        val fileOutStream = FileOutputStream(tempFile)
        inputStream.use { input ->
            fileOutStream.use { output ->
                input?.copyTo(output)
            }
        }
    }

    override fun stop() {
        super.stop()
        if (tempFile?.exists() == true) {
            tempFile?.delete()
        }
    }

    fun getCertificate(): Array<TrustManager> {
        val trustAllCerts = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<X509Certificate>,
                    authType: String
                ) {
                }

                override fun checkServerTrusted(
                    chain: Array<X509Certificate>,
                    authType: String
                ) {
                }

                override fun getAcceptedIssuers(): Array<X509Certificate> {
                    return emptyArray()
                }
            }
        )
        return trustAllCerts
    }
}