package ui

import security.AllowlistManager
import security.ApprovalManager
import server.McpServerManager
import java.awt.*
import java.awt.event.ActionEvent
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.border.TitledBorder
import javax.swing.table.DefaultTableModel

/**
 * Burp Suite tab UI for the MCP Companion Server extension.
 *
 * Controls:
 *  - Server status indicator
 *  - Auto-approve checkboxes (data access / all operations)
 *  - Allowlist management (add/remove hosts for auto-approved reads)
 */
class CompanionTab(private val serverManager: McpServerManager) : JPanel() {

    private val approvalManager: ApprovalManager = serverManager.approvalManager
    private val allowlistManager: AllowlistManager = serverManager.allowlistManager

    // Status
    private val statusDot = JLabel("●")
    private val statusLabel = JLabel("Running on http://127.0.0.1:${McpServerManager.DEFAULT_PORT}/sse")

    // Auto-approve checkboxes
    private val autoApproveDataCb = JCheckBox("Auto-approve data reads (get_sitemap, get_cookies, get_scope, get_scan_status)")
    private val autoApproveAllCb = JCheckBox("Auto-approve ALL operations including scans and scope changes  ⚠️")

    // Allowlist
    private val allowlistModel = DefaultTableModel(arrayOf("Host / Pattern"), 0)
    private val allowlistTable = JTable(allowlistModel)
    private val addHostField = JTextField(30)
    private val addHostBtn = JButton("Add")
    private val removeHostBtn = JButton("Remove selected")

    init {
        layout = BorderLayout(0, 12)
        border = EmptyBorder(16, 16, 16, 16)
        background = UIManager.getColor("Panel.background")

        add(buildStatusPanel(), BorderLayout.NORTH)
        add(buildCenterPanel(), BorderLayout.CENTER)

        refreshAllowlist()
        wireListeners()
    }

    // ── Status bar ─────────────────────────────────────────────────────────────

    private fun buildStatusPanel(): JPanel {
        val panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        panel.isOpaque = false

        statusDot.font = Font("Monospaced", Font.PLAIN, 18)
        statusDot.foreground = Color(0x2ecc40)   // green
        statusLabel.font = Font("SansSerif", Font.PLAIN, 13)

        panel.add(statusDot)
        panel.add(statusLabel)
        return panel
    }

    // ── Centre (approval + allowlist) ──────────────────────────────────────────

    private fun buildCenterPanel(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.isOpaque = false

        panel.add(buildApprovalPanel())
        panel.add(Box.createVerticalStrut(12))
        panel.add(buildAllowlistPanel())
        return panel
    }

    private fun buildApprovalPanel(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = titledBorder("Approval Settings")
        panel.isOpaque = false

        val note = JLabel("<html><b>Default behaviour:</b> every tool call shows a confirmation dialog. " +
            "Use the options below to reduce friction for trusted sessions.</html>")
        note.border = EmptyBorder(0, 0, 8, 0)
        note.alignmentX = Component.LEFT_ALIGNMENT

        autoApproveDataCb.isOpaque = false
        autoApproveDataCb.alignmentX = Component.LEFT_ALIGNMENT
        autoApproveDataCb.isSelected = approvalManager.autoApproveDataAccess

        autoApproveAllCb.isOpaque = false
        autoApproveAllCb.alignmentX = Component.LEFT_ALIGNMENT
        autoApproveAllCb.isSelected = approvalManager.autoApproveAll
        autoApproveAllCb.foreground = Color(0xcc2200)   // red — danger warning

        val scanNote = JLabel("<html><i>⚠️ Auto-approving ALL includes scans and scope changes. " +
            "Only enable during an active, controlled test session.</i></html>")
        scanNote.border = EmptyBorder(2, 24, 0, 0)
        scanNote.foreground = Color(0x888888)
        scanNote.alignmentX = Component.LEFT_ALIGNMENT

        panel.add(note)
        panel.add(autoApproveDataCb)
        panel.add(Box.createVerticalStrut(6))
        panel.add(autoApproveAllCb)
        panel.add(scanNote)
        return panel
    }

    private fun buildAllowlistPanel(): JPanel {
        val panel = JPanel(BorderLayout(0, 8))
        panel.border = titledBorder("Host Allowlist  (auto-approve data reads without a dialog)")
        panel.isOpaque = false

        val desc = JLabel("<html>Hosts listed here are auto-approved for READ-only tools " +
            "(get_sitemap, get_cookies) regardless of the checkbox above.<br>" +
            "Use exact hostname or wildcard: <code>*.example.com</code></html>")
        desc.border = EmptyBorder(0, 0, 6, 0)

        allowlistTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        allowlistTable.tableHeader.reorderingAllowed = false
        val scrollPane = JScrollPane(allowlistTable)
        scrollPane.preferredSize = Dimension(400, 140)

        val addRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        addRow.isOpaque = false
        addRow.add(JLabel("Host:"))
        addRow.add(addHostField)
        addRow.add(addHostBtn)
        addRow.add(removeHostBtn)

        panel.add(desc, BorderLayout.NORTH)
        panel.add(scrollPane, BorderLayout.CENTER)
        panel.add(addRow, BorderLayout.SOUTH)
        return panel
    }

    // ── Wiring ─────────────────────────────────────────────────────────────────

    private fun wireListeners() {
        autoApproveDataCb.addActionListener { _: ActionEvent ->
            approvalManager.autoApproveDataAccess = autoApproveDataCb.isSelected
            // If turning off all, also uncheck data
            if (!autoApproveDataCb.isSelected && autoApproveAllCb.isSelected) {
                autoApproveAllCb.isSelected = false
                approvalManager.autoApproveAll = false
            }
        }

        autoApproveAllCb.addActionListener { _: ActionEvent ->
            val selected = autoApproveAllCb.isSelected
            if (selected) {
                val confirm = JOptionPane.showConfirmDialog(
                    SwingUtilities.getWindowAncestor(this),
                    "Auto-approving ALL includes scans and scope modifications.\n" +
                        "Only do this during an active, controlled test.\n\nContinue?",
                    "Confirm Auto-Approve All",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                )
                if (confirm != JOptionPane.YES_OPTION) {
                    autoApproveAllCb.isSelected = false
                    return@addActionListener
                }
                // Also check data-access since all implies it
                autoApproveDataCb.isSelected = true
                approvalManager.autoApproveDataAccess = true
            }
            approvalManager.autoApproveAll = selected
        }

        addHostBtn.addActionListener {
            val host = addHostField.text.trim()
            if (host.isNotEmpty()) {
                allowlistManager.addHost(host)
                addHostField.text = ""
                refreshAllowlist()
            }
        }

        addHostField.addActionListener { addHostBtn.doClick() }  // Enter key

        removeHostBtn.addActionListener {
            val row = allowlistTable.selectedRow
            if (row >= 0) {
                val host = allowlistModel.getValueAt(row, 0) as String
                allowlistManager.removeHost(host)
                refreshAllowlist()
            }
        }
    }

    private fun refreshAllowlist() {
        allowlistModel.rowCount = 0
        allowlistManager.getAllowedHosts().sorted().forEach { host ->
            allowlistModel.addRow(arrayOf(host))
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun titledBorder(title: String) =
        BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), title,
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.BOLD, 12)
            ),
            EmptyBorder(8, 8, 8, 8)
        )
}
