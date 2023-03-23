package me.aisuneko.httpshare

import android.content.Context
import android.net.Uri
import android.security.KeyChain.getCertificateChain
import android.security.KeyChain.getPrivateKey
import android.util.Log
import me.aisuneko.httpshare.a.NanoHTTPD
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.*
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
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
        val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
// From https://www.washington.edu/itconnect/security/ca/load-der.crt
        val caInput: InputStream = BufferedInputStream(context.assets.open("cert.pem"))
        val ca: Certificate
        caInput.use { caInput ->
            ca = cf.generateCertificate(caInput)
            Log.e("Certificate", "ca=" + (ca as X509Certificate).subjectDN)
        }
// Create a KeyStore containing our trusted CAs

        val keyStoreStream: InputStream = context.resources.openRawResource(R.raw.keystore)
        val keyStorePassword = "123456".toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME)
        keyStore.load(keyStoreStream, keyStorePassword)

        val privateKey: PrivateKey? = getPrivateKey(context, "alias")
        val chain: Array<out X509Certificate>? = getCertificateChain(context, "alias")
        keyStore.setEntry(
            "alias", KeyStore.PrivateKeyEntry(privateKey, chain), KeyStore.PasswordProtection(
                keyStorePassword
            )
        )
        keyStore.setCertificateEntry("ca", ca)

        keyStore.setEntry(
            "alias",
            KeyStore.PrivateKeyEntry(privateKey, chain),
            KeyStore.PasswordProtection(keyStorePassword)
        )

        val keyManagerFactory =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, keyStorePassword)
        val trustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keyStore)


// Create a TrustManager that trusts the CAs in our KeyStore
        val tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
        val tmf = TrustManagerFactory.getInstance(tmfAlgorithm)
        tmf.init(keyStore)


// Create an SSLContext that uses our TrustManager
        val context = SSLContext.getInstance("TLS")
        context.init(
            keyManagerFactory.keyManagers,
            trustManagerFactory.trustManagers,
            SecureRandom()
        )

//        context.init(null, tmf.trustManagers, null)
        makeSecure(context.serverSocketFactory, arrayOf<String>("TLSv1.2", "TLSv1.3"))
//        makeSecure(makeSSLSocketFactory(keyStore,keyManagerFactory), arrayOf<String>("TLSv1.2","TLSv1.3"))

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