package com.yasser.securitylab

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private const val REPLICA_API_BASE = "https://yasser-security-lab-api-7w2p.onrender.com"

private data class ReplicaMcpTool(
    val name: String,
    val description: String,
    val inputSchema: String
)

@Composable
fun ReplicaMcpPanel(accessToken: String) {
    val scope = rememberCoroutineScope()
    var tools by remember { mutableStateOf<List<ReplicaMcpTool>>(emptyList()) }
    var selectedTool by remember { mutableStateOf("") }
    var argumentsJson by remember { mutableStateOf("{}") }
    var approved by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("اكتشف أدوات Replica MCP من الخادم الآمن.") }
    var resultText by remember { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text("Replica MCP — اتصال سحابي آمن", fontWeight = FontWeight.Bold)
            Text("يتم الاتصال عبر API بعد تسجيل الدخول. رمز MCP السري يبقى على الخادم ولا يُرسل إلى الهاتف.")
            Button(
                enabled = !busy,
                onClick = {
                    busy = true
                    resultText = ""
                    scope.launch {
                        try {
                            val response = withContext(Dispatchers.IO) {
                                replicaApiRequest("GET", "/v1/replica/tools", accessToken, null)
                            }
                            val array = response.optJSONArray("tools")
                            val discovered = buildList {
                                if (array != null) {
                                    for (index in 0 until array.length()) {
                                        val item = array.getJSONObject(index)
                                        add(
                                            ReplicaMcpTool(
                                                name = item.optString("name"),
                                                description = item.optString("description"),
                                                inputSchema = item.optJSONObject("input_schema")?.toString(2) ?: "{}"
                                            )
                                        )
                                    }
                                }
                            }
                            tools = discovered
                            selectedTool = discovered.firstOrNull()?.name.orEmpty()
                            status = if (discovered.isEmpty()) {
                                "لم يُرجع الخادم أدوات متاحة. تحقق من إعداد Replica MCP."
                            } else {
                                "تم اكتشاف ${discovered.size} أداة من Replica MCP."
                            }
                        } catch (error: Exception) {
                            status = "تعذر اكتشاف الأدوات: ${error.message ?: "خطأ غير معروف"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "جارٍ الاتصال..." else "اكتشاف أدوات Replica MCP") }

            tools.forEach { tool ->
                OutlinedButton(
                    enabled = !busy,
                    onClick = {
                        selectedTool = tool.name
                        argumentsJson = "{}"
                        approved = false
                        resultText = ""
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (selectedTool == tool.name) "✓ ${tool.name}" else tool.name)
                }
            }

            val selected = tools.firstOrNull { it.name == selectedTool }
            if (selected != null) {
                Text(selected.description)
                Text("مخطط المدخلات: ${selected.inputSchema}")
                OutlinedTextField(
                    value = argumentsJson,
                    onValueChange = { argumentsJson = it; approved = false },
                    label = { Text("وسائط الأداة بصيغة JSON") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = approved, onCheckedChange = { approved = it })
                    Text("أوافق على استدعاء هذه الأداة بهذه الوسائط الآن.")
                }
                Button(
                    enabled = !busy && approved,
                    onClick = {
                        busy = true
                        scope.launch {
                            try {
                                val args = JSONObject(argumentsJson)
                                val body = JSONObject()
                                    .put("tool_name", selectedTool)
                                    .put("arguments", args)
                                    .put("user_approved", true)
                                val response = withContext(Dispatchers.IO) {
                                    replicaApiRequest("POST", "/v1/replica/call", accessToken, body)
                                }
                                resultText = response.toString(2)
                                status = "اكتمل استدعاء الأداة. راجع النتيجة قبل المتابعة."
                            } catch (error: Exception) {
                                status = "فشل استدعاء الأداة: ${error.message ?: "تحقق من JSON والاتصال."}"
                            } finally {
                                approved = false
                                busy = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (busy) "جارٍ التنفيذ..." else "موافقة واستدعاء الأداة") }
            }

            Text(status)
            if (resultText.isNotBlank()) {
                Text("نتيجة MCP", fontWeight = FontWeight.Bold)
                Text(resultText)
            }
        }
    }
}

private fun replicaApiRequest(
    method: String,
    path: String,
    accessToken: String,
    body: JSONObject?
): JSONObject {
    val connection = (URL(REPLICA_API_BASE + path).openConnection() as HttpURLConnection).apply {
        requestMethod = method
        connectTimeout = 15000
        readTimeout = 120000
        setRequestProperty("Authorization", "Bearer $accessToken")
        setRequestProperty("Accept", "application/json")
        if (body != null) {
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
    }
    try {
        if (body != null) {
            connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val responseText = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            val detail = try {
                JSONObject(responseText).optString("detail", "HTTP $code")
            } catch (_: Exception) {
                "HTTP $code"
            }
            throw IOException(detail)
        }
        return JSONObject(responseText)
    } finally {
        connection.disconnect()
    }
}
