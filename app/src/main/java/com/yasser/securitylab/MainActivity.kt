package com.yasser.securitylab

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection

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

@Composable
fun SecurityLabApp() {
    val context = LocalContext.current
    fun open(url: String) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        MaterialTheme(
            colorScheme = lightColorScheme(
                primary = Red, background = Paper, surface = Color.White,
                onPrimary = Color.White, onBackground = Ink, onSurface = Ink
            )
        ) {
            Column(
                modifier = Modifier.fillMaxSize().background(Paper)
                    .verticalScroll(rememberScrollState()).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("مختبر ياسر الأمني", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Ink)
                        Text("منصة تحليل أمني مصرح به", color = Muted, fontSize = 12.sp)
                    }
                    Surface(color = Red, shape = RoundedCornerShape(14.dp)) {
                        Text("YSL", color = Color.White, modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp), fontWeight = FontWeight.Bold)
                    }
                }
                Card(colors = CardDefaults.cardColors(containerColor = Ink), shape = RoundedCornerShape(20.dp)) {
                    Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("مركز الفحص", color = Color.White, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                        Text("26 أداة موصولة بسير عمل GitHub Actions. الفحوصات النشطة تتطلب تأكيد الإذن وتحديد هدف واحد.", color = Color(0xFFE4E0DA))
                        Button(onClick = { open("https://github.com/yasserbenmaghnia812-arch/Yasser-Security-Lab/actions/workflows/security-static.yml") },
                            colors = ButtonDefaults.buttonColors(containerColor = Red), modifier = Modifier.fillMaxWidth()) {
                            Text("تشغيل فحص الكود والملفات")
                        }
                        OutlinedButton(onClick = { open("https://github.com/yasserbenmaghnia812-arch/Yasser-Security-Lab/actions/workflows/security-network-approved.yml") },
                            modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)) {
                            Text("فحص شبكة مصرح به")
                        }
                    }
                }
                Text("الأدوات المرتبطة", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                ToolGroup("تحليل الكود والاعتماديات", "Semgrep • Gitleaks • Trivy • Checkov • Syft • Grype • YARA • ClamAV", "متاح عبر GitHub Actions")
                ToolGroup("تحليل تطبيقات Android", "MobSF • JADX • Apktool • Androguard • APKLeaks • Ghidra • radare2", "ضع APK المصرح به داخل authorized-samples/ لتشغيل 7 محللات")
                ToolGroup("الشبكات والويب", "Nmap • ZAP • Nuclei • httpx • Subfinder • Amass • dnsx • Katana • Naabu • testssl.sh • Nikto", "تشغيل يدوي مع تأكيد الإذن")
                Text("قيد الدمج", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                ToolGroup("أداة لم تكتمل", "mitmproxy", "تحتاج ربط وكيل اعتراض محلي مع جهازك")
                Text("النتائج والتقارير", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Button(onClick = { open("https://github.com/yasserbenmaghnia812-arch/Yasser-Security-Lab/actions") },
                    modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Ink)) {
                    Text("عرض سجلات الفحص والتقارير")
                }
                OutlinedButton(onClick = { open("https://github.com/yasserbenmaghnia812-arch/Yasser-Security-Lab") },
                    modifier = Modifier.fillMaxWidth()) {
                    Text("المستودع والإعدادات")
                }
                Text("تنبيه: التطبيق يفتح سير العمل السحابي؛ الربط المباشر بين API والتطبيق لم يكتمل بعد.", color = Muted, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun ToolGroup(title: String, tools: String, status: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, fontWeight = FontWeight.Bold, color = Ink)
            Text(tools, color = Ink, fontSize = 12.sp)
            Text(status, color = Red, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}
