package me.aisuneko.httpshare

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.documentfile.provider.DocumentFile
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.fragment_first.*
import me.aisuneko.httpshare.databinding.ActivityMainBinding
import java.io.IOException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

const val PICK_CODE = 114

class MainActivity : AppCompatActivity() {

    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var binding: ActivityMainBinding
    private var webServer: Server? = null
    private var isServerOn = false

    //    private fun log(str: String) {
//        textview_first.text = textview_first.text.toString() + "\n" + str
//    }
    private fun closeServer() {
        if (this.webServer != null) {
            this.webServer?.closeAllConnections()
            this.webServer?.stop()
            this.isServerOn = false
            this.webServer = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        val navController = findNavController(R.id.nav_host_fragment_content_main)
        appBarConfiguration = AppBarConfiguration(navController.graph)
        setupActionBarWithNavController(navController, appBarConfiguration)

        binding.fab.setOnClickListener {
            val intent = Intent()
                .setType("*/*")
                .setAction(Intent.ACTION_GET_CONTENT)
            if (!isServerOn) {
                startActivityForResult(Intent.createChooser(intent, "Select a file"), PICK_CODE)
            } else {
                val start_icon =
                    this.resources.getIdentifier("@android:drawable/ic_media_play", null, null)
                fab.setImageResource(start_icon)
                Snackbar.make(binding.root, "Server shutdown", Snackbar.LENGTH_LONG)
                    .setAnchorView(R.id.fab)
                    .setAction("Action", null).show()
                textview_first.text = getString(R.string.idle)
                closeServer()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        closeServer()
    }


    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment_content_main)
        return navController.navigateUp(appBarConfiguration)
                || super.onSupportNavigateUp()
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

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_CODE && resultCode == RESULT_OK) {
            try {
                val selectedFile = data?.data // The URI with the location of the file
                if (selectedFile != null) {
                    val realFile: DocumentFile? = DocumentFile.fromSingleUri(this, selectedFile)
                    val fileName: String? = realFile?.name
                    webServer = Server(selectedFile, fileName ?: "null", this)
                    webServer!!.start()
                    isServerOn = true

                    val serverRunningStr = getString(
                        R.string.server_running,
                        NetworkUtils.getLocalIpAddress(),
                        webServer?.listeningPort
                    )
                    textview_first.text = fileName + "\n" + serverRunningStr
                    val stop_icon =
                        this.resources.getIdentifier("@android:drawable/ic_media_stop", null, null)
                    fab.setImageResource(stop_icon)
                    Snackbar.make(binding.root, serverRunningStr, Snackbar.LENGTH_LONG)
                        .setAnchorView(R.id.fab)
                        .setAction("Action", null).show()

                }
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    }
}