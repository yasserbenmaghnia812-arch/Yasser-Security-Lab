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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private const val REPLICATE_MCP_BRIDGE = "http://127.0.0.1:8765"

private data class ReplicaMcpTool(
    val name: String,
    val description: String
)

@Composable
fun ReplicaMcpPanel() {
    val scope = rememberCoroutineScope()
    var bridgeToken by remember { mutableStateOf("") }
    var tools by remember { mutableStateOf<List<ReplicaMcpTool>>(emptyList()) }
    var selectedTool by remember { mutableStateOf("") }
    var argumentsJson by remember { mutableStateOf("{}") }
    var approved by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("شغّل Replicate MCP Bridge من Termux أولاً.") }
    var resultText by remember { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            Text("Replicate MCP", fontWeight = FontWeight.Bold)
            Text("اتصال محلي عبر Termux. لا تضع مفتاح Replicate هنا؛ أدخل رمز الجسر المحلي فقط.")
            OutlinedTextField(
                value = bridgeToken,
                onValueChange = { bridgeToken = it },
                label = { Text("رمز الجسر المحلي") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
            )
            Button(
                enabled = !busy && bridgeToken.isNotBlank(),
                onClick = {
                    busy = true
                    resultText = ""
                    scope.launch {
                        try {
                            val discovered = withContext(Dispatchers.IO) {
                                val response = bridgeRequest("GET", "/v1/mcp/tools", bridgeToken, null)
                                val array = response.getJSONArray("tools")
                                buildList {
                                    for (index in 0 until array.length()) {
                                        val item = array.getJSONObject(index)
                                        add(
                                            ReplicaMcpTool(
                                                item.optString("name"),
                                                item.optString("description")
                                            )
                                        )
                                    }
                                }
                            }
                            tools = discovered
                            selectedTool = discovered.firstOrNull()?.name.orEmpty()
                            status = "تم اكتشاف ${discovered.size} أداة من Replicate MCP."
                        } catch (error: Exception) {
                            status = "تعذر الاتصال: ${error.message ?: "تحقق من Termux والرمز المحلي."}"
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (busy) "جارٍ الاتصال..." else "اكتشاف أدوات MCP")
            }
            Text(status)
            if (tools.isNotEmpty()) {
                Text("اختر الأداة", fontWeight = FontWeight.SemiBold)
                tools.take(12).forEach { tool ->
                    OutlinedButton(
                        onClick = {
                            selectedTool = tool.name
                            approved = false
                            resultText = ""
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(if (selectedTool == tool.name) "✓ ${tool.name}" else tool.name)
                            if (tool.description.isNotBlank()) {
                                Text(tool.description.take(180))
                            }
                        }
                    }
                }
                if (tools.size > 12) {
                    Text("تُعرض أول 12 أداة فقط في هذه الشاشة.")
                }
                OutlinedTextField(
                    value = selectedTool,
                    onValueChange = { selectedTool = it; approved = false },
                    label = { Text("اسم الأداة المحددة") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = argumentsJson,
                    onValueChange = { argumentsJson = it; approved = false },
                    label = { Text("وسائط الأداة بصيغة JSON") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3
                )
                Text("قد تنشئ بعض الأدوات تنبؤات سحابية مدفوعة على Replicate. راجع اسم الأداة والوسائط قبل الموافقة.")
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Checkbox(checked = approved, onCheckedChange = { approved = it })
                    Text("أوافق على استدعاء هذه الأداة بهذه الوسائط.")
                }
                Button(
                    enabled = !busy && approved && selectedTool.isNotBlank() && bridgeToken.isNotBlank(),
                    onClick = {
                        busy = true
                        scope.launch {
                            try {
                                val args = JSONObject(argumentsJson)
                                val body = JSONObject()
                                    .put("name", selectedTool.trim())
                                    .put("arguments", args)
                                    .put("user_approved", true)
                                val response = withContext(Dispatchers.IO) {
                                    bridgeRequest("POST", "/v1/mcp/call", bridgeToken, body)
                                }
                                resultText = response.toString(2)
                                status = "اكتمل استدعاء ${selectedTool}."
                            } catch (error: Exception) {
                                resultText = ""
                                status = "فشل الاستدعاء: ${error.message ?: "خطأ غير معروف"}"
                            } finally {
                                approved = false
                                busy = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (busy) "جارٍ التنفيذ..." else "تنفيذ الأداة بعد الموافقة")
                }
            }
            if (resultText.isNotBlank()) {
                Text("النتيجة", fontWeight = FontWeight.SemiBold)
                Text(resultText)
            }
        }
    }
}

private fun bridgeRequest(
    method: String,
    path: String,
    token: String,
    body: JSONObject?
): JSONObject {
    val connection = (URL(REPLICATE_MCP_BRIDGE + path).openConnection() as HttpURLConnection).apply {
        requestMethod = method
        connectTimeout = 5000
        readTimeout = 120000
        setRequestProperty("Accept", "application/json")
        setRequestProperty("Authorization", "Bearer $token")
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
        val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            val message = try { JSONObject(text).optString("error", "HTTP $code") } catch (_: Exception) { "HTTP $code" }
            throw IOException(message)
        }
        return JSONObject(text)
    } finally {
        connection.disconnect()
    }
}
