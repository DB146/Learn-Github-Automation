package com.example.tvvoice

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.util.Locale

class VoiceAssistantActivity : AppCompatActivity() {

    private lateinit var speechRecognizer: SpeechRecognizer
    private lateinit var recognizerIntent: Intent

    // Package names
    private val PKG_SMARTTUBE = "com.liskovsoft.smarttubetv.beta" // Change to com.liskovsoft.smarttube if using stable
    private val PKG_FPTPLAY = "com.fpt.play.tv"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request audio permission if missing
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.RECORD_AUDIO), 100)
            return
        }

        initSpeechRecognizer()
    }

    private fun initSpeechRecognizer() {
        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(this)
        recognizerIntent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, "vi-VN") // Default to Vietnamese, or Locale.getDefault()
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
        }

        speechRecognizer.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                Toast.makeText(this@VoiceAssistantActivity, "Listening...", Toast.LENGTH_SHORT).show()
            }
            override fun onBeginningOfSpeech() {}
            override fun onRmsChanged(rmsdB: Float) {}
            override fun onBufferReceived(buffer: ByteArray?) {}
            override fun onEndOfSpeech() {}
            
            override fun onError(error: Int) {
                finish()
            }

            override fun onResults(results: Bundle?) {
                val matches = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                if (!matches.isNullOrEmpty()) {
                    handleCommand(matches[0].lowercase(Locale.ROOT).trim())
                }
                finish()
            }

            override fun onPartialResults(partialResults: Bundle?) {}
            override fun onEvent(eventType: Int, params: Bundle?) {}
        })

        speechRecognizer.startListening(recognizerIntent)
    }

    private fun handleCommand(text: String) {
        // Rule 2: Check FPT Play (vtv1 through vtv9)
        val vtvRegex = Regex("vtv[1-9]")
        if (vtvRegex.containsMatchIn(text)) {
            launchApp(PKG_FPTPLAY)
            return
        }

        // Rule 1: SmartTube logic
        if (text == "youtube" || text == "smarttube") {
            launchApp(PKG_SMARTTUBE)
        } else if (text.contains("youtube") || text.contains("smarttube")) {
            // Contains other words -> open SmartTube and pass search query
            // SmartTube search deep link format: smarttube://results?search_query=... or standard view intent
            try {
                val searchQuery = text.replace("youtube", "").replace("smarttube", "").trim()
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse("smarttube://results?search_query=$searchQuery")).apply {
                    setPackage(PKG_SMARTTUBE)
                }
                startActivity(intent)
            } catch (e: Exception) {
                // Fallback to launching app normally if deep link fails
                launchApp(PKG_SMARTTUBE)
            }
        } else {
            Toast.makeText(this, "Unrecognized: $text", Toast.LENGTH_SHORT).show()
        }
    }

    private fun launchApp(packageName: String) {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        if (intent != null) {
            startActivity(intent)
        } else {
            Toast.makeText(this, "App not installed: $packageName", Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::speechRecognizer.isInitialized) {
            speechRecognizer.destroy()
        }
    }
}
