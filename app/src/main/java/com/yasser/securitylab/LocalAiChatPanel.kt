package com.yasser.securitylab

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Connects to LocalMind's OpenAI-compatible local API.
 * The default endpoint is loopback-only; no paid provider or cloud API is used.
 */
@Composable
fun LocalAiChatPanel() {
    val scope = rememberCoroutineScope()
    var baseUrl by remember { mutableStateOf("http://127.0.0.1:8000/v1") }
    var apiKey by remember { mutableStateOf("") }
    var modelId by remember { mutableStateOf("") }
    var prompt by remember { mutableStateOf("") }
    var answer by remember { mutableStateOf("حمّل نموذجاً محلياً في LocalMind، ثم شغّل Local API وأدخل بيانات الاتصال هنا.") }
    var busy by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text("مساعد محلي — LocalMind", fontWeight = FontWeight.Bold)
            Text("تُرسل الرسائل إلى النموذج الموجود على هذا الهاتف عبر اتصال محلي، دون Claude أو API مدفوع.")
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("عنوان Local API") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = modelId,
                onValueChange = { modelId = it },
                label = { Text("معرّف النموذج من LocalMind") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it },
                label = { Text("مفتاح Local API") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
            )
            OutlinedTextField(
                value = prompt,
                onValueChange = { prompt = it },
                label = { Text("اكتب طلبك") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2
            )
            Button(
                enabled = !busy && prompt.isNotBlank() && modelId.isNotBlank() && apiKey.isNotBlank(),
                onClick = {
                    val endpoint = baseUrl.trim().trimEnd('/')
                    val selectedModel = modelId.trim()
                    val secret = apiKey.trim()
                    val question = prompt.trim()
                    busy = true
                    scope.launch {
                        try {
                            answer = withContext(Dispatchers.IO) {
                                completeLocalChat(endpoint, selectedModel, secret, question)
                            }
                            prompt = ""
                        } catch (error: Exception) {
                            answer = "تعذر الاتصال بالنموذج المحلي: ${error.message ?: "خطأ غير معروف"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (busy) "جارٍ التفكير..." else "إرسال إلى النموذج المحلي")
            }
            Text(if (busy) "النموذج يعالج الطلب..." else answer)
        }
    }
}

private fun completeLocalChat(
    baseUrl: String,
    modelId: String,
    apiKey: String,
    prompt: String
): String {
    val parsed = URL(baseUrl)
    val host = parsed.host.lowercase()
    if (parsed.protocol != "http" || host !in setOf("127.0.0.1", "localhost", "::1")) {
        throw IOException("يسمح هذا الإصدار باتصال محلي فقط: 127.0.0.1 أو localhost.")
    }
    val connection = (URL("$baseUrl/chat/completions").openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10000
        readTimeout = 120000
        doOutput = true
        setRequestProperty("Authorization", "Bearer $apiKey")
        setRequestProperty("Content-Type", "application/json")
    }
    try {
        val body = JSONObject()
            .put("model", modelId)
            .put("messages", JSONArray().put(JSONObject().put("role", "user").put("content", prompt)))
            .put("stream", false)
            .toString()
            .toByteArray(Charsets.UTF_8)
        connection.outputStream.use { it.write(body) }
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val responseText = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (status !in 200..299) {
            val detail = try {
                JSONObject(responseText).optString("error", responseText)
            } catch (_: Exception) { responseText }
            throw IOException("HTTP $status: $detail")
        }
        val content = JSONObject(responseText)
            .getJSONArray("choices")
            .getJSONObject(0)
            .getJSONObject("message")
            .optString("content")
        if (content.isBlank()) throw IOException("أعاد النموذج رداً فارغاً.")
        return content
    } finally {
        connection.disconnect()
    }
}
