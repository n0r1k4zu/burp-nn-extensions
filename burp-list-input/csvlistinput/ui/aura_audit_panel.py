# -*- coding: utf-8 -*-
"""MyTools-native Aura Diagnostic target and low-volume reconnaissance UI."""
from threading import Thread
import time
from java.awt import BorderLayout, FlowLayout, Color, Dimension
from java.lang import Runnable
from java.io import File
from javax.swing import (JButton, JCheckBox, JLabel, JPanel, JScrollPane, JTextArea, JTextField,
                         SwingUtilities, JFileChooser, JTable, JTabbedPane, BoxLayout)
from javax.swing.table import AbstractTableModel
import json
import csv
from csvlistinput import aura_audit_engine

class _UiRunnable(Runnable):
    def __init__(self, fn): self.fn = fn
    def run(self): self.fn()

class _AuditTableModel(AbstractTableModel):
    columns = ['Category', 'Name', 'Value', 'Status']
    def __init__(self): AbstractTableModel.__init__(self); self.rows = []
    def set_rows(self, rows): self.rows = rows; self.fireTableDataChanged()
    def getRowCount(self): return len(self.rows)
    def getColumnCount(self): return len(self.columns)
    def getColumnName(self, col): return self.columns[col]
    def getValueAt(self, row, col): return self.rows[row][col]

class AuraAuditPanel(JPanel):
    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks, self.helpers = callbacks, helpers
        self.log_fn, self.error_fn = log_fn, error_fn
        self.session = None
        self.object_inventory = []
        self.last_extract = {}
        self.cancel_requested = False
        self.audit_rows = []
        self.active = JCheckBox('Enable active Aura requests (authorized target only)', False,
                                actionPerformed=self._on_active)
        self.guestify = JButton('Guest mode (remove Cookie)', actionPerformed=self._on_guestify); self.guestify.setEnabled(False)
        self.detect_endpoint = JButton('Detect Aura endpoint', actionPerformed=self._on_detect_endpoint); self.detect_endpoint.setEnabled(False)
        self.recon = JButton('Run reconnaissance', actionPerformed=self._on_recon); self.recon.setEnabled(False)
        self.check_objects = JCheckBox('Object configuration', True)
        self.check_counts = JCheckBox('Object counts', True)
        self.check_listui = JCheckBox('List UI check', True)
        self.check_selfreg = JCheckBox('Self-registration', True)
        self.check_graphql = JCheckBox('GraphQL availability', True)
        self.check_home = JCheckBox('Home URLs', True)
        self.check_apex = JCheckBox('Apex controller references', True)
        self.object_field = JTextField(16); self.object_field.setToolTipText('Object API name from reconnaissance')
        self.extract_cap = JTextField('5000', 5); self.extract_delay = JTextField('200', 4)
        self.extract_button = JButton('Extract records', actionPerformed=self._on_extract); self.extract_button.setEnabled(False)
        self.cancel_extract = JButton('Cancel extract', actionPerformed=self._on_cancel_extract); self.cancel_extract.setEnabled(False)
        self.export_json = JButton('Export JSON', actionPerformed=self._on_export_json); self.export_json.setEnabled(False)
        self.export_csv = JButton('Export CSV', actionPerformed=self._on_export_csv); self.export_csv.setEnabled(False)
        self.export_recon = JButton('Export reconnaissance JSON', actionPerformed=self._on_export_recon); self.export_recon.setEnabled(False)

        # Keep the original Aura Helper workflow visible as three sub-tabs:
        # target setup -> reconnaissance -> record extraction.  The former
        # single toolbar made all controls compete for one horizontal row.
        self.target_panel = self._build_target_panel()
        self.recon_panel = self._build_recon_panel()
        self.extract_panel = self._build_extract_panel()
        self.subtabs = JTabbedPane()
        self.subtabs.addTab('1. Target setup', self.target_panel)
        self.subtabs.addTab('2. Reconnaissance', self.recon_panel)
        self.subtabs.addTab('3. Data extraction', self.extract_panel)
        self.add(self.subtabs, BorderLayout.CENTER)

        note = JTextArea('This diagnostic sends HTTP requests to the captured target. Use it only on an authorized assessment target. '
                         'Set a target from Proxy History with the MyTools Aura diagnostic context-menu action, then enable active requests.')
        note.setEditable(False); note.setLineWrap(True); note.setWrapStyleWord(True); note.setRows(2)
        note.setBackground(self.getBackground())
        self.add(note, BorderLayout.SOUTH)

        self.audit_model = _AuditTableModel()
        self.audit_table = JTable(self.audit_model)
        self.extract_model = _AuditTableModel()
        self.extract_table = JTable(self.extract_model)
        self.recon_output = JTextArea(8, 80); self.recon_output.setEditable(False); self.recon_output.setLineWrap(True)
        self.extract_output = JTextArea(8, 80); self.extract_output.setEditable(False); self.extract_output.setLineWrap(True)
        self.output = self.recon_output
        self.status = JLabel('Set a target from a captured Aura request: right-click in Proxy History -> MyTools: Set Aura diagnostic target.')
        # The status line is intentionally outside the subtabs so it remains
        # visible while switching between the three workflow stages.
        status_panel = JPanel(BorderLayout()); status_panel.add(self.status, BorderLayout.CENTER)
        self.add(status_panel, BorderLayout.NORTH)

        # Tables are installed after construction so the models can be shared
        # by the existing worker callbacks without changing their semantics.
        self.recon_panel.add(JScrollPane(self.audit_table), BorderLayout.CENTER)
        self.recon_panel.add(JScrollPane(self.recon_output), BorderLayout.SOUTH)
        self.extract_panel.add(JScrollPane(self.extract_table), BorderLayout.CENTER)
        self.extract_panel.add(JScrollPane(self.extract_output), BorderLayout.SOUTH)

    def _build_target_panel(self):
        panel = JPanel(BorderLayout())
        content = JPanel(); content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        row = JPanel(FlowLayout(FlowLayout.LEFT)); row.add(self.active); row.add(self.guestify); row.add(self.detect_endpoint)
        content.add(row)
        target = JLabel('Current target: (not set)')
        target.setOpaque(True); target.setBackground(Color(255, 230, 150)); target.setForeground(Color.BLACK)
        self.target_label = target
        target_row = JPanel(FlowLayout(FlowLayout.LEFT)); target_row.add(target); content.add(target_row)
        hint = JTextArea('Recommended: right-click an Aura request in Proxy History and choose '
                         'MyTools: Set Aura diagnostic target. Guest mode removes Cookie and resets aura.token.')
        hint.setEditable(False); hint.setLineWrap(True); hint.setWrapStyleWord(True); hint.setRows(3)
        hint.setBackground(panel.getBackground()); content.add(hint)
        panel.add(content, BorderLayout.NORTH)
        return panel

    def _build_recon_panel(self):
        panel = JPanel(BorderLayout())
        top = JPanel(); top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        checks = JPanel(FlowLayout(FlowLayout.LEFT))
        for component in (self.check_objects, self.check_counts, self.check_listui, self.check_selfreg,
                          self.check_graphql, self.check_home, self.check_apex):
            checks.add(component)
        top.add(checks)
        actions = JPanel(FlowLayout(FlowLayout.LEFT)); actions.add(self.recon); actions.add(self.export_recon)
        top.add(actions)
        panel.add(top, BorderLayout.NORTH)
        return panel

    def _build_extract_panel(self):
        panel = JPanel(BorderLayout())
        top = JPanel(); top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        row = JPanel(FlowLayout(FlowLayout.LEFT)); row.add(JLabel('Object API name:')); row.add(self.object_field)
        row.add(JLabel('Max records:')); row.add(self.extract_cap); row.add(JLabel('Delay ms:')); row.add(self.extract_delay)
        top.add(row)
        actions = JPanel(FlowLayout(FlowLayout.LEFT)); actions.add(self.extract_button); actions.add(self.cancel_extract)
        actions.add(self.export_json); actions.add(self.export_csv); top.add(actions)
        panel.add(top, BorderLayout.NORTH)
        return panel

    def set_target_message(self, message):
        try:
            session = aura_audit_engine.extract_session_from_request(self.helpers.bytesToString(message.getRequest()))
            if not session: raise ValueError('No usable aura.context was found in this request.')
            session['http_service'] = message.getHttpService()
            self.session = session
            self.status.setText('Target set: %s (captured session; active sending is OFF).' % session['endpoint_path'])
            self.target_label.setText('Current target: %s' % session['endpoint_path'])
            self.recon_output.setText('Captured Aura target\nendpoint: %s\napp: %s\nfwuid: %s\n' %
                                (session['endpoint_path'], session['app'], session['fwuid']))
            self._update_controls()
        except Exception as e:
            self.status.setText('Aura target setup failed: %s' % e)
            if self.error_fn: self.error_fn('Aura Diagnostic', self.status.getText())

    def _update_controls(self):
        self.recon.setEnabled(bool(self.session) and self.active.isSelected())
        self.guestify.setEnabled(bool(self.session))
        self.detect_endpoint.setEnabled(bool(self.session) and self.active.isSelected())
        self.extract_button.setEnabled(bool(self.session) and self.active.isSelected() and bool(self.object_field.getText().strip()))

    def _on_active(self, event): self._update_controls()

    def _on_guestify(self, event):
        if not self.session: return
        self.session['cookie'] = ''; self.session['token'] = 'undefined'
        self.status.setText('Guest mode enabled: Cookie removed and aura.token reset.')

    def _on_detect_endpoint(self, event):
        if not self.session or not self.active.isSelected(): return
        self.detect_endpoint.setEnabled(False); Thread(target=self._detect_endpoint_worker).start()

    def _detect_endpoint_worker(self):
        candidates = ['/s/sfsites/aura', '/s/sfsites/aura/aura', '/aura', '/aura/']
        found = []
        try:
            for path in candidates:
                body = aura_audit_engine.build_post_body([], self.session['context'], self.session['token'], self.session['page_uri'])
                svc = self.session['http_service']; raw = ('POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s' % (path, svc.getHost(), body))
                item = self.callbacks.makeHttpRequest(svc, self.helpers.stringToBytes(raw))
                text = self.helpers.bytesToString(item.getResponse()) if item and item.getResponse() else ''
                if aura_audit_engine.endpoint_response_looks_valid(text): found.append(path)
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._endpoint_done(found)))
        except Exception as e:
            SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._failed(error)))

    def _endpoint_done(self, found):
        if found:
            self.session['endpoint_path'] = found[0]
            self.status.setText('Aura endpoint detected: %s' % found[0])
        else: self.status.setText('No candidate Aura endpoint detected.')
        self._update_controls()

    def _on_recon(self, event):
        if not self.session or not self.active.isSelected(): return
        self.recon.setEnabled(False); self.status.setText('Running Aura reconnaissance...')
        Thread(target=self._run_recon).start()

    def _run_recon(self):
        try:
            enabled = {'objects': self.check_objects.isSelected(), 'counts': self.check_counts.isSelected(),
                       'list_ui': self.check_listui.isSelected(), 'self_registration': self.check_selfreg.isSelected(),
                       'graphql': self.check_graphql.isSelected(), 'home_urls': self.check_home.isSelected()}
            enabled['apex'] = self.check_apex.isSelected()
            by_id = self._send_actions(aura_audit_engine.recon_actions(enabled))
            lines = ['Aura reconnaissance response: %d action(s)' % len(by_id)]
            rows = []
            for action_id in sorted(by_id):
                state = by_id[action_id].get('state', '')
                lines.append('%s: %s' % (action_id, state)); rows.append(['Action', action_id, '', state])
            enabled_action = by_id.get('selfreg;enabled'); url_action = by_id.get('selfreg;url')
            if enabled_action is not None:
                reg_enabled, reg_url = aura_audit_engine.parse_self_registration_result(enabled_action, url_action)
                lines.append('Self registration: %s%s' % ('enabled' if reg_enabled else 'disabled', (' (' + str(reg_url) + ')' if reg_url else '')))
                rows.append(['Self registration', 'enabled', reg_url or '', 'enabled' if reg_enabled else 'disabled'])
            home_urls = aura_audit_engine.parse_home_urls_result(by_id.get('5;a'))
            if home_urls:
                lines.append('Home URLs:')
                for name, url in sorted(home_urls.items()):
                    lines.append('%s: %s' % (name, url)); rows.append(['Home URL', name, url, 'found'])
            if enabled.get('apex'):
                apex_names = self._discover_apex_references()
                lines.append('Apex controller references: %d' % len(apex_names))
                for name in sorted(apex_names): lines.append(name); rows.append(['Apex', name, '', 'found'])
            config = aura_audit_engine.parse_config_result(by_id.get('1;a'))
            objects = sorted(config.keys())
            self.object_inventory = objects
            lines.append('Objects discovered: %d' % len(objects))
            rows.extend(['Object', name, config.get(name, ''), 'found'] for name in objects)
            if objects and (enabled.get('counts') or enabled.get('list_ui')):
                follow_up = []
                for index, name in enumerate(objects[:100]):
                    if enabled.get('counts'): follow_up.append(aura_audit_engine.build_object_count_action('count;%d' % index, name))
                    if enabled.get('list_ui'): follow_up.append(aura_audit_engine.build_list_views_action('views;%d' % index, name))
                details = self._send_actions(follow_up)
                for index, name in enumerate(objects[:100]):
                    count = aura_audit_engine.parse_count_result(details.get('count;%d' % index))
                    views = aura_audit_engine.parse_list_views_result(details.get('views;%d' % index))
                    has_records = False
                    if views:
                        item_action = self._send_actions([aura_audit_engine.build_list_items_action('item;%d' % index, name, views[0])])
                        has_records = aura_audit_engine.parse_list_items_result(item_action.get('item;%d' % index))
                    lines.append('%s: count=%s, listViews=%d, records=%s' % (name, count if count is not None else '?', len(views), has_records))
                    rows.append(['Object', name, 'count=%s; listViews=%d' % (count if count is not None else '?', len(views)), 'records' if has_records else 'no records'])
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._done('\n'.join(lines), rows)))
        except Exception as e:
            SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._failed(error)))

    def _done(self, text, rows=None):
        if rows is not None: self.audit_rows = rows; self.audit_model.set_rows(rows); self.export_recon.setEnabled(True)
        self.recon_output.setText(text); self.status.setText('Aura reconnaissance completed.'); self._update_controls()
    def _failed(self, error):
        self.status.setText('Aura reconnaissance failed: %s' % error); self._update_controls()
        self.cancel_extract.setEnabled(False)
        if self.error_fn: self.error_fn('Aura Diagnostic', self.status.getText())

    def _on_extract(self, event):
        if not self.session or not self.active.isSelected(): return
        name = self.object_field.getText().strip()
        if not name: return
        self.extract_button.setEnabled(False); self.cancel_extract.setEnabled(True)
        self.cancel_requested = False; self.status.setText('Extracting records for %s...' % name)
        Thread(target=self._run_extract, args=(name,)).start()

    def _on_cancel_extract(self, event):
        self.cancel_requested = True
        self.status.setText('Cancel requested; finishing current Aura page...')

    def _run_extract(self, object_name):
        try:
            cap = max(1, int(str(self.extract_cap.getText()).strip()))
            delay = max(0, int(str(self.extract_delay.getText()).strip())) / 1000.0
            fields_resp = self._send_actions([aura_audit_engine.build_graphql_fields_action('fields;1', [object_name])])
            fields = aura_audit_engine.parse_graphql_fields_result(fields_resp.get('fields;1'))
            names = fields.get(object_name, [])
            rows = []
            if names:
                cursor = None
                for page in range(max(1, (cap + 1999) // 2000)):
                    if self.cancel_requested: break
                    if page and delay: time.sleep(delay)
                    page_size = min(2000, cap - len(rows))
                    if page_size <= 0: break
                    responses = self._send_actions([aura_audit_engine.build_graphql_rows_action('rows;%d' % page, object_name, names, page_size, cursor)])
                    page_rows, cursor, more, total = aura_audit_engine.parse_graphql_rows_result(responses.get('rows;%d' % page), object_name, names)
                    rows.extend(page_rows[:max(0, cap - len(rows))])
                    if not more: break
            else:
                responses = self._send_actions([aura_audit_engine.build_getitems_records_action('items;1', object_name, 2000, 1)])
                rows = aura_audit_engine.parse_getitems_records_result(responses.get('items;1'))[:cap]
            self.last_extract[object_name] = rows
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._extract_done(object_name, rows)))
        except Exception as e:
            SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._failed(error)))

    def _extract_done(self, object_name, rows):
        table_rows = []
        for index, record in enumerate(rows):
            for field, value in (record or {}).items(): table_rows.append(['Record', '%s:%d' % (object_name, index), field, value])
        self.extract_model.set_rows(table_rows)
        self.extract_output.setText('Extracted %d record(s) for %s\n%s' % (len(rows), object_name, json.dumps(rows, ensure_ascii=False, indent=2)))
        self.status.setText('Record extraction completed.'); self.extract_button.setEnabled(True); self.cancel_extract.setEnabled(False)
        self.export_json.setEnabled(True); self.export_csv.setEnabled(True)

    def _choose_export(self, suffix):
        chooser = JFileChooser(); chooser.setSelectedFile(File('aura_extracted.' + suffix))
        return chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION, chooser.getSelectedFile()

    def _on_export_json(self, event):
        if not self.last_extract: return
        try:
            ok, path = self._choose_export('json')
            if not ok: return
            with open(path.getAbsolutePath(), 'wb') as handle:
                handle.write(json.dumps(self.last_extract, ensure_ascii=False, indent=2).encode('utf-8'))
            self.status.setText('JSON export completed: %s' % path.getAbsolutePath())
        except Exception as e: self._failed(e)

    def _on_export_csv(self, event):
        if not self.last_extract: return
        try:
            ok, path = self._choose_export('csv')
            if not ok: return
            with open(path.getAbsolutePath(), 'wb') as handle:
                writer = csv.writer(handle); writer.writerow(['ObjectApiName', 'RecordIndex', 'FieldName', 'FieldValue'])
                for obj, rows in self.last_extract.items():
                    for index, row in enumerate(rows):
                        for field, value in row.items(): writer.writerow([obj, index, field, value])
            self.status.setText('CSV export completed: %s' % path.getAbsolutePath())
        except Exception as e: self._failed(e)

    def _on_export_recon(self, event):
        if not self.audit_rows: return
        try:
            ok, path = self._choose_export('json')
            if not ok: return
            with open(path.getAbsolutePath(), 'wb') as handle:
                handle.write(json.dumps(self.audit_rows, ensure_ascii=False, indent=2).encode('utf-8'))
            self.status.setText('Reconnaissance JSON export completed: %s' % path.getAbsolutePath())
        except Exception as e: self._failed(e)

    def _send_actions(self, actions):
        if not actions: return {}
        body = aura_audit_engine.build_post_body(actions, self.session['context'], self.session['token'], self.session['page_uri'])
        svc = self.session['http_service']; host = svc.getHost()
        headers = ['POST %s HTTP/1.1' % self.session['endpoint_path'], 'Host: %s' % host,
                   'Content-Type: application/x-www-form-urlencoded', 'Content-Length: %d' % len(body)]
        if self.session.get('cookie'): headers.append('Cookie: ' + self.session['cookie'])
        raw = '\r\n'.join(headers) + '\r\n\r\n' + body
        response = self.callbacks.makeHttpRequest(svc, self.helpers.stringToBytes(raw))
        text = self.helpers.bytesToString(response.getResponse()) if response and response.getResponse() else ''
        return aura_audit_engine.responses_by_id(aura_audit_engine.parse_response(text.split('\r\n\r\n', 1)[-1]))

    def _discover_apex_references(self):
        """Fetch only the captured page/resources and inspect their text."""
        paths = [self.session.get('page_uri') or '/']
        found = set()
        for path in paths:
            try:
                request = 'GET %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (path, self.session['http_service'].getHost())
                response = self.callbacks.makeHttpRequest(self.session['http_service'], self.helpers.stringToBytes(request))
                text = self.helpers.bytesToString(response.getResponse()) if response and response.getResponse() else ''
                body = text.split('\r\n\r\n', 1)[-1]
                found.update(aura_audit_engine.parse_apex_controller_names(body))
                for resource in aura_audit_engine.parse_resource_urls(body)[:20]:
                    if resource.startswith('http'): continue
                    req = 'GET %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (resource, self.session['http_service'].getHost())
                    item = self.callbacks.makeHttpRequest(self.session['http_service'], self.helpers.stringToBytes(req))
                    resource_text = self.helpers.bytesToString(item.getResponse()) if item and item.getResponse() else ''
                    found.update(aura_audit_engine.parse_apex_controller_names(resource_text))
            except Exception:
                continue
        return found
