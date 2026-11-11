package com.yasser.securitylab

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private const val AGENT_API_BASE = "https://yasser-security-lab-api-7w2p.onrender.com"
private const val AGENT_ACTIONS_URL = "https://github.com/yasserbenmaghnia812-arch/Yasser-Security-Lab/actions/workflows/agent-approved-task.yml"

@Composable
fun AgentTaskPanel(accessToken: String) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var taskType by remember { mutableStateOf("api_tests") }
    var planText by remember { mutableStateOf("") }
    var approved by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("اختر مهمة لعرض خطتها قبل التنفيذ.") }
    var requestId by remember { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("وكيل تنفيذ المهام بموافقة المستخدم", fontWeight = FontWeight.Bold)
            Text("ينفّذ مهاماً محددة مسبقاً فقط. لا يقبل أوامر Shell حرة ولا يغيّر ملفات المصدر تلقائياً.")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    enabled = !busy,
                    onClick = { taskType = "api_tests"; planText = ""; approved = false; requestId = "" }
                ) { Text(if (taskType == "api_tests") "✓ اختبارات API" else "اختبارات API") }
                OutlinedButton(
                    enabled = !busy,
                    onClick = { taskType = "android_debug_apk"; planText = ""; approved = false; requestId = "" }
                ) { Text(if (taskType == "android_debug_apk") "✓ بناء APK" else "بناء APK") }
            }
            Button(
                enabled = !busy,
                onClick = {
                    busy = true
                    approved = false
                    scope.launch {
                        try {
                            val body = JSONObject().put("task_type", taskType)
                            val response = withContext(Dispatchers.IO) {
                                agentRequest("/v1/agent/plan", accessToken, body)
                            }
                            val steps = response.optJSONArray("steps")
                            val rendered = buildString {
                                append(response.optString("title"))
                                if (steps != null) {
                                    for (index in 0 until steps.length()) {
                                        append("\n").append(index + 1).append(". ").append(steps.optString(index))
                                    }
                                }
                            }
                            planText = rendered
                            status = "هذه معاينة؛ لم يبدأ التنفيذ."
                        } catch (error: Exception) {
                            status = "تعذر إنشاء الخطة: ${error.message ?: "خطأ غير معروف"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "جارٍ تجهيز الخطة..." else "عرض خطة المهمة") }

            if (planText.isNotBlank()) {
                Text(planText)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = approved, onCheckedChange = { approved = it })
                    Text("أوافق على تشغيل المهمة المحددة أعلاه.")
                }
                Button(
                    enabled = !busy && approved,
                    onClick = {
                        busy = true
                        scope.launch {
                            try {
                                val body = JSONObject()
                                    .put("task_type", taskType)
                                    .put("user_approved", true)
                                val response = withContext(Dispatchers.IO) {
                                    agentRequest("/v1/agent/execute", accessToken, body)
                                }
                                requestId = response.optString("request_id")
                                status = "قبل GitHub Actions المهمة. النتيجة النهائية تظهر بعد انتهاء التشغيل."
                            } catch (error: Exception) {
                                status = "تعذر إرسال المهمة: ${error.message ?: "خطأ غير معروف"}"
                            } finally {
                                approved = false
                                busy = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (busy) "جارٍ الإرسال..." else "الموافقة والتنفيذ") }
            }
            Text(status)
            if (requestId.isNotBlank()) {
                Text("رقم تتبع المهمة: $requestId")
                OutlinedButton(
                    onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(AGENT_ACTIONS_URL))) },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("فتح سجل مهام الوكيل في GitHub Actions") }
            }
        }
    }
}

private fun agentRequest(path: String, token: String, body: JSONObject): JSONObject {
    val connection = (URL(AGENT_API_BASE + path).openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 15000
        readTimeout = 30000
        doOutput = true
        setRequestProperty("Authorization", "Bearer $token")
        setRequestProperty("Content-Type", "application/json")
        setRequestProperty("Accept", "application/json")
    }
    try {
        connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            val detail = try { JSONObject(text).optString("detail", "HTTP $code") } catch (_: Exception) { "HTTP $code" }
            throw IOException(detail)
        }
        return JSONObject(text)
    } finally {
        connection.disconnect()
    }
}
