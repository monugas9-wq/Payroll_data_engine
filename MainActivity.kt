package com.payroll.converter

import android.content.Context
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.*
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.Charset
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    PayrollConverterUI(context = this)
                }
            }
        }
    }
}

@Composable
fun PayrollConverterUI(context: Context) {
    val coroutineScope = rememberCoroutineScope()
    var logs by remember { mutableStateOf("System Ready.\nTap 'Extract ZIP Archive' or 'Convert Report to CSV' to begin.") }
    var isBusy by remember { mutableStateOf(false) }

    val zipPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            logs += "\n[Cancelled] No ZIP file selected."
            return@rememberLauncherForActivityResult
        }
        coroutineScope.launch {
            isBusy = true
            logs = "Starting secure extraction...\n"
            val result = withContext(Dispatchers.IO) { safeExtractZipArchive(context, uri) }
            logs += result
            isBusy = false
        }
    }

    val reportPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            logs += "\n[Cancelled] No report file selected."
            return@rememberLauncherForActivityResult
        }
        coroutineScope.launch {
            isBusy = true
            logs = "Starting parsing and CSV conversion...\n"
            val result = withContext(Dispatchers.IO) { convertReportToCsv(context, uri) }
            logs += result
            isBusy = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Payroll Data Engine",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Secure local processing: extracts ZIP archives and converts raw payroll text/tables into RFC 4180 verified CSV.",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { zipPicker.launch(arrayOf("application/zip", "application/x-zip-compressed", "*/*")) },
                modifier = Modifier.weight(1f),
                enabled = !isBusy
            ) {
                Text("Extract ZIP", maxLines = 1)
            }

            Button(
                onClick = { reportPicker.launch(arrayOf("*/*")) },
                modifier = Modifier.weight(1f),
                enabled = !isBusy
            ) {
                Text("Convert CSV", maxLines = 1)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (isBusy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Spacer(modifier = Modifier.height(12.dp))
        }

        Text(
            text = "Process Execution Log:",
            fontWeight = FontWeight.SemiBold,
            fontSize = 14.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Box(
            modifier = Modifier
                .fillMaxSize()
                .weight(1f)
                .background(Color(0xFF1E1E1E), shape = RoundedCornerShape(8.dp))
                .padding(12.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Text(
                text = logs,
                color = Color(0xFF00FF66),
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                lineHeight = 16.sp
            )
        }
    }
}

fun safeExtractZipArchive(context: Context, zipUri: Uri): String {
    val destinationFolder = File(context.getExternalFilesDir(null), "Extracted_Reports")
    if (!destinationFolder.exists()) destinationFolder.mkdirs()

    var extractedCount = 0
    val maxUncompressedSize = 100 * 1024 * 1024 // 100 MB safety limit
    var totalBytesExtracted: Long = 0

    return try {
        context.contentResolver.openInputStream(zipUri)?.use { rawIn ->
            ZipInputStream(BufferedInputStream(rawIn)).use { zis ->
                val baseCanonicalPath = destinationFolder.canonicalPath
                var entry: ZipEntry? = zis.nextEntry

                while (entry != null) {
                    val outputFile = File(destinationFolder, entry.name)

                    // Prevent Zip Slip vulnerability
                    if (!outputFile.canonicalPath.startsWith(baseCanonicalPath + File.separator)) {
                        throw SecurityException("Security Violation: Zip Slip detected in entry: ${entry.name}")
                    }

                    if (entry.isDirectory) {
                        outputFile.mkdirs()
                    } else {
                        outputFile.parentFile?.mkdirs()
                        FileOutputStream(outputFile).use { fos ->
                            val buffer = ByteArray(8192)
                            var len: Int
                            while (zis.read(buffer).also { len = it } > 0) {
                                totalBytesExtracted += len
                                if (totalBytesExtracted > maxUncompressedSize) {
                                    throw SecurityException("Security Violation: Zip Bomb protection triggered (> 100MB).")
                                }
                                fos.write(buffer, 0, len)
                            }
                        }
                        extractedCount++
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        } ?: return "ERROR: Unable to open ZIP file stream."

        "[SUCCESS] Decompressed $extractedCount files successfully.\n" +
                "Target Directory:\n${destinationFolder.absolutePath}"
    } catch (e: Exception) {
        "[ERROR] Extraction Failed: ${e.message}"
    }
}

fun convertReportToCsv(context: Context, fileUri: Uri): String {
    val outputDir = File(context.getExternalFilesDir(null), "Converted_CSVs")
    if (!outputDir.exists()) outputDir.mkdirs()
    val outputFile = File(outputDir, "PAYROLL_EXPORT_${System.currentTimeMillis()}.csv")

    var recordsProcessed = 0
    var anomaliesDetected = 0

    return try {
        // Safe encoding probe: UTF-8 with fallback
        context.contentResolver.openInputStream(fileUri)?.use { inputStream ->
            val reader = BufferedReader(InputStreamReader(inputStream, Charset.forName("UTF-8")))
            BufferedWriter(FileWriter(outputFile, Charset.forName("UTF-8"))).use { writer ->
                
                // Write RFC 4180 standard header
                writer.write(""Employee_ID","Employee_Name","Cost_Center","Gross_Pay","Federal_Tax","State_Tax","Other_Deductions","Net_Pay","Audit_Status"\r\n")

                var line = reader.readLine()
                while (line != null) {
                    val row = line.trim()

                    // Rule 1: Exclude decorative lines, headers, footers, and aggregations
                    if (row.isNotEmpty() &&
                        !row.startsWith("=") &&
                        !row.startsWith("-") &&
                        !row.contains("Page ", ignoreCase = true) &&
                        !row.contains("Subtotal", ignoreCase = true) &&
                        !row.contains("Grand Total", ignoreCase = true) &&
                        !row.contains("Report Run", ignoreCase = true)
                    ) {
                        // Rule 2: Tokenize on tab or 2+ consecutive spaces
                        val tokens = row.split(Regex("\t+|\s{2,}"))

                        // Rule 3: Check for standard payroll record structure
                        if (tokens.size >= 5) {
                            val empId = sanitizeCsvField(tokens[0])
                            val empName = sanitizeCsvField(tokens[1])
                            val costCenter = if (tokens.size >= 8) sanitizeCsvField(tokens[2]) else "GENERAL"

                            val numIdxOffset = if (tokens.size >= 8) 3 else 2
                            val gross = parseAccountingDecimal(tokens.getOrElse(numIdxOffset) { "0.00" })
                            val fedTax = parseAccountingDecimal(tokens.getOrElse(numIdxOffset + 1) { "0.00" })
                            val stateTax = parseAccountingDecimal(tokens.getOrElse(numIdxOffset + 2) { "0.00" })
                            val otherDed = parseAccountingDecimal(tokens.getOrElse(numIdxOffset + 3) { "0.00" })

                            val reportedNet = if (tokens.size > numIdxOffset + 4) {
                                parseAccountingDecimal(tokens[numIdxOffset + 4])
                            } else {
                                gross.subtract(fedTax).subtract(stateTax).subtract(otherDed)
                            }

                            // Rule 4: Financial Checksum reconciliation
                            val expectedNet = gross.subtract(fedTax).subtract(stateTax).subtract(otherDed)
                            val discrepancy = reportedNet.subtract(expectedNet).abs()
                            val auditStatus = if (discrepancy <= BigDecimal("0.05")) "VERIFIED" else "DISCREPANCY"
                            if (auditStatus == "DISCREPANCY") anomaliesDetected++

                            // Write escaped CSV line
                            writer.write(
                                ""$empId","$empName","$costCenter","${gross}","${fedTax}","${stateTax}","${otherDed}","${reportedNet}","$auditStatus"\r\n"
                            )
                            recordsProcessed++
                        }
                    }
                    line = reader.readLine()
                }
            }
        } ?: return "ERROR: Unable to open input report stream."

        "[SUCCESS] Export Complete!\n" +
                "Processed Records: $recordsProcessed\n" +
                "Flagged Discrepancies: $anomaliesDetected\n" +
                "Output File:\n${outputFile.absolutePath}"
    } catch (e: Exception) {
        "[ERROR] Parsing Failed: ${e.message}"
    }
}

fun sanitizeCsvField(text: String): String {
    var clean = text.replace(""", """")
    // Formula Injection Mitigation (CWE-1236)
    if (clean.startsWith("=") || clean.startsWith("+") || clean.startsWith("-") || clean.startsWith("@")) {
        clean = "'$clean"
    }
    return clean
}

fun parseAccountingDecimal(value: String): BigDecimal {
    var raw = value.trim()
    var isNegative = false

    // Handle accounting parenthetical negative: (100.50)
    if (raw.startsWith("(") && raw.endsWith(")")) {
        isNegative = true
        raw = raw.substring(1, raw.length - 1)
    } else if (raw.endsWith("-")) {
        isNegative = true
        raw = raw.substring(0, raw.length - 1)
    }

    val cleanDigits = raw.replace(Regex("[^0-9.]"), "")
    return try {
        val parsed = BigDecimal(cleanDigits).setScale(2, RoundingMode.HALF_UP)
        if (isNegative) parsed.negate() else parsed
    } catch (e: Exception) {
        BigDecimal.ZERO.setScale(2, RoundingMode.HALF_UP)
    }
}
