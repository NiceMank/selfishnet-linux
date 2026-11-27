package com.selfishnet.companion

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.selfishnet.companion.ui.SelfishNetApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val deepLinkUri = intent?.dataString
        setContent {
            SelfishNetApp(initialPairingUri = deepLinkUri)
        }
    }
}
