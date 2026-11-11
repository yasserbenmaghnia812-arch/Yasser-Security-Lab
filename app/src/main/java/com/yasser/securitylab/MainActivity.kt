package com.yasser.securitylab

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

private const val API_BASE = "https://yasser-security-lab-api-7w2p.onrender.com"
private val Ink = Color(0xFF191919)
private val Paper = Color(0xFFF5F3EF)
private val Red = Color(0xFFD94B45)
private val Muted = Color(0xFF77736E)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SecurityLabApp() }
    }
}

private object Api {
    fun request(method: String, url: String, headers: Map<String, String> = emptyMap(), body: ByteArray? = null, contentType: String? = null): JSONObject {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 20000
            readTimeout = 90000
            headers.forEach { (key, value) -> setRequestProperty(key, value) }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", contentType ?: "application/json")
                setFixedLengthStreamingMode(body.size)
            }
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (status !in 200..299) {
                val message = try {
                    val json = JSONObject(text)
                    json.optString("detail", json.optString("msg", json.optString("message", "HTTP $status")))
                } catch (_: Exception) { "HTTP $status: $text" }
                throw IOException(message)
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        } finally {
            connection.disconnect()
        }
    }

    fun config(): JSONObject = request("GET", "$API_BASE/v1/config")

    fun auth(supabaseUrl: String, key: String, email: String, password: String, create: Boolean): JSONObject {
        val endpoint = if (create) "signup" else "token?grant_type=password"
        val body = JSONObject().put("email", email).put("password", password).toString().toByteArray()
        return request(
            "POST", "$supabaseUrl/auth/v1/$endpoint",
            mapOf("apikey" to key, "Accept" to "application/json"),
            body, "application/json"
        )
    }

    fun upload(uri: Uri, context: Context, token: String, note: String): JSONObject {
        val name = context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        } ?: "selected.apk"
        if (!name.lowercase().endsWith(".apk")) throw IOException("اختر ملف APK فقط.")
        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IOException("تعذر قراءة الملف المحدد.")
        if (bytes.size > 80 * 1024 * 1024) throw IOException("الحد الأقصى للملف 80 MB في هذه النسخة.")
        if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4b.toByte()) throw IOException("الملف لا يبدو APK صالحاً.")
        val queryName = URLEncoder.encode(name, "UTF-8")
        val queryNote = URLEncoder.encode(note, "UTF-8")
        return request(
            "POST", "$API_BASE/v1/apks/upload?file_name=$queryName&authorization_note=$queryNote",
            mapOf("Authorization" to "Bearer $token", "Accept" to "application/json"),
            bytes, "application/vnd.android.package-archive"
        )
    }

    fun job(token: String, id: String): JSONObject =
        request("GET", "$API_BASE/v1/jobs/$id", mapOf("Authorization" to "Bearer $token"))
}

@Composable
fun SecurityLabApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var supabaseUrl by remember { mutableStateOf("") }
    var publishableKey by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var authorizationNote by remember { mutableStateOf("أملك هذا التطبيق أو لدي إذن صريح من مالكه لتحليله أمنياً.") }
    var accessToken by remember { mutableStateOf<String?>(null) }
    var userEmail by remember { mutableStateOf("") }
    var selectedApk by remember { mutableStateOf<Uri?>(null) }
    var jobId by remember { mutableStateOf("") }
    var jobStatus by remember { mutableStateOf("") }
    var reportUrl by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("جارٍ الاتصال بخادم API...") }
    var busy by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        try {
            val config = withContext(Dispatchers.IO) { Api.config() }
            supabaseUrl = config.getString("supabase_url")
            publishableKey = config.getString("supabase_publishable_key")
            message = "اتصال API جاهز. سجّل الدخول للبدء."
        } catch (e: Exception) {
            message = "تعذر الاتصال بـ API: ${e.message}"
        }
    }

    LaunchedEffect(jobId, accessToken) {
        val token = accessToken
        if (jobId.isNotBlank() && token != null) {
            while (true) {
                delay(10000)
                try {
                    val status = withContext(Dispatchers.IO) { Api.job(token, jobId) }
                    jobStatus = status.optString("status", "unknown")
                    reportUrl = status.optJSONObject("github_run")?.optString("url").orEmpty()
                    if (jobStatus == "succeeded" || jobStatus == "failed") {
                        message = if (jobStatus == "succeeded") "اكتمل التحليل. التقارير متاحة في GitHub Actions." else "فشل التحليل. افتح سجل التشغيل لمعرفة الخطأ."
                        break
                    }
                } catch (_: Exception) {
                    // Retry on the next interval without losing the current status.
                }
            }
        }
    }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        selectedApk = uri
        if (uri != null) message = "تم اختيار ملف APK. أكد الإذن ثم ارفع الملف للتحليل."
    }

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        MaterialTheme(colorScheme = lightColorScheme(primary = Red, background = Paper, surface = Color.White, onPrimary = Color.White, onBackground = Ink, onSurface = Ink)) {
            Column(
                Modifier.fillMaxSize().background(Paper).verticalScroll(rememberScrollState()).padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("مختبر ياسر الأمني", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Ink)
                        Text("تحليل APK سحابي — نسخة تشغيلية أولية", color = Muted, fontSize = 12.sp)
                    }
                    Surface(color = Red, shape = RoundedCornerShape(14.dp)) {
                        Text("YSL", color = Color.White, modifier = Modifier.padding(14.dp), fontWeight = FontWeight.Bold)
                    }
                }

                Card(colors = CardDefaults.cardColors(containerColor = Ink), shape = RoundedCornerShape(18.dp)) {
                    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("حالة الخدمة", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text(message, color = Color(0xFFE9E4DE), fontSize = 13.sp)
                    }
                }

                LocalAiChatPanel()

                if (accessToken == null) {
                    Card(shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("تسجيل الدخول", fontWeight = FontWeight.Bold, fontSize = 19.sp)
                            OutlinedTextField(email, { email = it }, label = { Text("البريد الإلكتروني") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                            OutlinedTextField(password, { password = it }, label = { Text("كلمة المرور") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(enabled = !busy && supabaseUrl.isNotBlank(), onClick = {
                                    busy = true
                                    scope.launch {
                                        try {
                                            val data = withContext(Dispatchers.IO) { Api.auth(supabaseUrl, publishableKey, email.trim(), password, false) }
                                            accessToken = data.optString("access_token").takeIf { it.isNotBlank() }
                                            userEmail = email.trim()
                                            message = if (accessToken != null) "تم تسجيل الدخول." else "لم تُرجع المصادقة جلسة دخول. تحقق من البريد وتأكيد الحساب."
                                        } catch (e: Exception) { message = "فشل الدخول: ${e.message}" }
                                        finally { busy = false }
                                    }
                                }) { Text("دخول") }
                                OutlinedButton(enabled = !busy && supabaseUrl.isNotBlank(), onClick = {
                                    busy = true
                                    scope.launch {
                                        try {
                                            val data = withContext(Dispatchers.IO) { Api.auth(supabaseUrl, publishableKey, email.trim(), password, true) }
                                            accessToken = data.optString("access_token").takeIf { it.isNotBlank() }
                                            userEmail = email.trim()
                                            message = if (accessToken != null) "تم إنشاء الحساب وتسجيل الدخول." else "تم إرسال طلب التسجيل. إذا كان تأكيد البريد مفعلاً، افتح رسالة التأكيد ثم سجّل الدخول."
                                        } catch (e: Exception) { message = "فشل إنشاء الحساب: ${e.message}" }
                                        finally { busy = false }
                                    }
                                }) { Text("إنشاء حساب") }
                            }
                        }
                    }
                } else {
                    Card(shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("الحساب: $userEmail", fontWeight = FontWeight.Bold)
                            OutlinedTextField(
                                authorizationNote, { authorizationNote = it },
                                label = { Text("إثبات ملكية التطبيق أو الإذن") },
                                modifier = Modifier.fillMaxWidth(), minLines = 2
                            )
                            Text("رفع APK للتحليل", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                            OutlinedButton(onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, modifier = Modifier.fillMaxWidth()) {
                                Text(if (selectedApk == null) "اختيار ملف APK من الهاتف" else "تغيير الملف المحدد")
                            }
                            if (selectedApk != null) Text(selectedApk?.lastPathSegment ?: "ملف APK محدد", color = Muted, fontSize = 12.sp)
                            Button(enabled = !busy && selectedApk != null && authorizationNote.length >= 12, onClick = {
                                val uri = selectedApk ?: return@Button
                                val token = accessToken ?: return@Button
                                busy = true
                                message = "جارٍ رفع APK إلى التخزين الخاص..."
                                scope.launch {
                                    try {
                                        val result = withContext(Dispatchers.IO) { Api.upload(uri, context, token, authorizationNote) }
                                        jobId = result.getString("job_id")
                                        jobStatus = result.optString("status", "queued")
                                        message = "تم رفع APK وإرسال مهمة التحليل. رقم المهمة: $jobId"
                                    } catch (e: Exception) { message = "فشل الرفع أو بدء التحليل: ${e.message}" }
                                    finally { busy = false }
                                }
                            }, modifier = Modifier.fillMaxWidth()) { Text(if (busy) "جارٍ التنفيذ..." else "رفع وتشغيل JADX + Apktool + MobSF") }
                        }
                    }

                    if (jobId.isNotBlank()) {
                        Card(shape = RoundedCornerShape(18.dp)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("متابعة التحليل", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                                Text("المهمة: $jobId", fontSize = 11.sp, color = Muted)
                                Text("الحالة: $jobStatus", fontWeight = FontWeight.SemiBold)
                                Button(enabled = !busy, onClick = {
                                    val token = accessToken ?: return@Button
                                    busy = true
                                    scope.launch {
                                        try {
                                            val status = withContext(Dispatchers.IO) { Api.job(token, jobId) }
                                            jobStatus = status.optString("status", "unknown")
                                            reportUrl = status.optJSONObject("github_run")?.optString("url").orEmpty()
                                            message = when (jobStatus) {
                                                "succeeded" -> "اكتمل التحليل. افتح سجل GitHub Actions لتنزيل التقارير."
                                                "failed" -> "فشل التحليل. افتح سجل التشغيل لمعرفة الخطأ."
                                                else -> "المهمة ما زالت قيد التنفيذ: $jobStatus"
                                            }
                                        } catch (e: Exception) { message = "تعذر تحديث الحالة: ${e.message}" }
                                        finally { busy = false }
                                    }
                                }, modifier = Modifier.fillMaxWidth()) { Text("تحديث حالة المهمة") }
                                if (reportUrl.isNotBlank()) {
                                    OutlinedButton(onClick = {
                                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(reportUrl)))
                                    }, modifier = Modifier.fillMaxWidth()) {
                                        Text("فتح التقارير في GitHub Actions")
                                    }
                                }
                            }
                        }
                    }

                    OutlinedButton(onClick = {
                        accessToken = null
                        userEmail = ""
                        jobId = ""
                        jobStatus = ""
                        reportUrl = ""
                        message = "تم تسجيل الخروج من الجلسة الحالية."
                    }, modifier = Modifier.fillMaxWidth()) { Text("تسجيل الخروج") }
                }

                Text("الأدوات التي ينفذها مسار APK: JADX وApktool وMobSF. لا تعرض الواجهة نجاحاً حتى تؤكد GitHub Actions اكتمال المهمة.", color = Muted, fontSize = 11.sp)
            }
        }
    }
}
