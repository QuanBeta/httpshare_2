package me.aisuneko.httpshare

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.core.net.toFile
import fi.iki.elonen.NanoHTTPD.getMimeTypeForFile
import me.aisuneko.httpshare.a.NanoHTTPD
import java.io.*
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
//    override fun serve(session: IHTTPSession?): Response {
//        return Response(Response.Status.OK, mime, FileInputStream(tempFile))
//    }

    override fun serve(session: IHTTPSession): Response? {
        val headers = session.headers
        val parms = session.parms
        val method = session.method
        val uri = session.uri
        val files: Map<String, String> = HashMap()
        if (Method.POST == method || Method.PUT == method) {
            try {
                session.parseBody(files)
            } catch (e: IOException) {
                return getResponse("Internal Error IO Exception: " + e.message)
            } catch (e: ResponseException) {
                return Response(e.status, MIME_PLAINTEXT, e.message)
            }
        }
        return serveFile(uri, headers, tempFile!!)
    }

    private fun serveFile(uri: String, header: Map<String, String>, file: File): Response? {
        println("--------------------------------------------------------")
        header.map {
            println("key, ${it.key} value ${it.value}")
        }
        println("--------------------------------------------------------")
        var res: Response?
        val mime = getMimeTypeForFile(uri)
        try {
            val etag = Integer.toHexString(
                (file.absolutePath +
                        file.lastModified() + "" + file.length()).hashCode()
            )
            var startFrom: Long = 0
            var endAt: Long = -1
            var range = header["range"]
            if (range != null) {
                if (range.startsWith("bytes=")) {
                    range = range.substring("bytes=".length)
                    val minus = range.indexOf('-')
                    try {
                        if (minus > 0) {
                            startFrom = range.substring(0, minus).toLong()
                            endAt = range.substring(minus + 1).toLong()
                        }
                    } catch (ignored: NumberFormatException) {
                    }
                }
            }
            val fileLen = file.length()
            if (range != null && startFrom >= 0) {
                if (startFrom >= fileLen) {
                    res = createResponse(Response.Status.RANGE_NOT_SATISFIABLE, MIME_PLAINTEXT, "")
                    res!!.addHeader("Content-Range", "bytes 0-0/$fileLen")
                    res.addHeader("ETag", etag)
                } else {
                    if (endAt < 0) {
                        endAt = fileLen - 1
                    }
                    //endAt=startFrom+1000000;
                    var newLen = endAt - startFrom + 1
                    if (newLen < 0) {
                        newLen = 0
                    }
                    val dataLen = newLen
                    val fis: FileInputStream = object : FileInputStream(file) {
                        @Throws(IOException::class)
                        override fun available(): Int {
                            return dataLen.toInt()
                        }
                    }
                    fis.skip(startFrom)
                    res = createResponse(Response.Status.PARTIAL_CONTENT, mime, fis, dataLen)
                    res!!.addHeader("Content-Length", "" + dataLen)
                    res.addHeader(
                        "Content-Range", "bytes " + startFrom + "-" +
                                endAt + "/" + fileLen
                    )
                    res.addHeader("ETag", etag)
                    Log.d("Server", "serveFile --1--: Start:$startFrom End:$endAt")
                }
            } else {
                if (etag == header["if-none-match"]) {
                    res = createResponse(Response.Status.NOT_MODIFIED, mime, "")
                    Log.d("Server", "serveFile --2--: Start:$startFrom End:$endAt")
                } else {
                    val fis = FileInputStream(file)
                    res = createResponse(
                        Response.Status.OK, mime, fis,
                        fis.available().toLong()
                    )
                    res!!.addHeader("Content-Length", "" + fileLen)
                    res.addHeader("ETag", etag)
                    Log.d("Server", "serveFile --3--: Start:$startFrom End:$endAt")
                }
            }
        } catch (ioe: IOException) {
            res = getResponse("Forbidden: Reading file failed")
        }
        return res ?: getResponse("Error 404: File not found")
    }

    private fun createResponse(
        status: Response.Status,
        mimeType: String,
        message: InputStream,
        totalBytes: Long
    ): Response? {
        val res: Response = Response(status, mimeType, message)
        res.addHeader("Accept-Ranges", "bytes")
        return res
    }

    private fun createResponse(
        status: Response.Status,
        mimeType: String,
        message: String
    ): Response? {
        val res: Response = Response(status, mimeType, message)
        res.addHeader("Accept-Ranges", "bytes")
        return res
    }

    private fun getResponse(message: String): Response? {
        return createResponse(Response.Status.OK, "text/plain", message)
    }

    override fun start() {
        val inputStream2: InputStream = context.assets.open("mycert.crt")
        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val certificate: X509Certificate =
            certificateFactory.generateCertificate(inputStream2) as X509Certificate

        // Create a keystore and store the certificate in it
        val keyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(context.resources.openRawResource(R.raw.keystore), "123456".toCharArray())
        keyStore.setCertificateEntry("mycert", certificate)

        // Create a KeyManagerFactory and initialize it with the keystore
        val keyManagerFactory: KeyManagerFactory =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, "123456".toCharArray())

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
}