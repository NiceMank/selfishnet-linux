package com.mynetfilter.companion

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.mynetfilter.companion.ui.MyNetFilterApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val deepLinkUri = intent?.dataString
        setContent {
            MyNetFilterApp(initialPairingUri = deepLinkUri)
        }
    }
}
