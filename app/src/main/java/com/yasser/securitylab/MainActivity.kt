package com.yasser.securitylab

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
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("مختبر ياسر الأمني", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Ink)
                        Text("تحليل أمني مصرح به • لوحة التحكم", color = Muted, fontSize = 12.sp)
                    }
                    Surface(color = Red, shape = RoundedCornerShape(14.dp)) {
                        Text("YSL", color = Color.White, modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp), fontWeight = FontWeight.Bold)
                    }
                }
                Card(colors = CardDefaults.cardColors(containerColor = Ink), shape = RoundedCornerShape(20.dp)) {
                    Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("مركز التحليل", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                        Text("أدر أصولك، شغّل الفحوصات المصرح بها، وراجع الأدلة والتقارير.", color = Color(0xFFE4E0DA))
                        Button(onClick = {}, colors = ButtonDefaults.buttonColors(containerColor = Red)) {
                            Text("إضافة أصل مصرح به")
                        }
                    }
                }
                Text("الأقسام", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                SectionCard("فحص الأصول", "نطاقات IP ومواقع تملكها أو لديك إذن بفحصها")
                SectionCard("تحليل APK", "تحليل ثابت، مكونات التطبيق، الأذونات والمؤشرات")
                SectionCard("الهندسة العكسية", "فحص الملفات الثنائية والتبعيات بشكل آمن")
                SectionCard("الدردشة الذكية", "مساعدان لتحليل النتائج واقتراح الإصلاحات")
                SectionCard("التقارير", "الأدلة، الخطورة، الثقة، والتوصيات")
                SectionCard("الإعدادات", "الخادم، النماذج، الخصوصية، وسجل الموافقات")
                Text("الإصدار التمهيدي 0.1.0 — التنفيذ السحابي غير مربوط بعد", color = Muted, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, subtitle: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(title, fontWeight = FontWeight.Bold, color = Ink)
            Text(subtitle, color = Muted, fontSize = 12.sp)
        }
    }
}
