import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QDialog, QLabel,
    QLineEdit, QTextEdit, QComboBox, QDateEdit, QSpinBox, QMessageBox,
    QTabWidget, QHeaderView, QInputDialog, QCheckBox, QProgressBar
)
from PyQt5.QtCore import Qt, QDate, QTimer, QItemSelectionModel, QEvent
from PyQt5.QtGui import QColor, QFont
import base64
import time

class EncryptionHandler:
    @staticmethod
    def encrypt(text, password):
        result = "".join([chr(ord(text[i]) ^ ord(password[i % len(password)])) for i in range(len(text))])
        return base64.b64encode(result.encode()).decode()
    @staticmethod
    def decrypt(encrypted_text, password):
        try:
            decoded = base64.b64decode(encrypted_text.encode()).decode()
            result = "".join([chr(ord(decoded[i]) ^ ord(password[i % len(password)])) for i in range(len(decoded))])
            return result
        except:
            return None

class TaskDialog(QDialog):
    def __init__(self, parent=None, task=None):
        super().__init__(parent)
        self.task = task
        self.setWindowTitle("Task Details")
        self.setGeometry(100, 100, 600, 550)
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Task (max 256 characters):"))
        self.task_input = QTextEdit()
        self.task_input.setMaximumHeight(60)
        if self.task:
            self.task_input.setPlainText(self.task.get('task', ''))
        layout.addWidget(self.task_input)
        layout.addWidget(QLabel("Priority:"))
        self.priority_input = QComboBox()
        self.priority_input.addItems(['Low', 'Medium', 'High', 'Unassigned'])
        if self.task:
            self.priority_input.setCurrentText(self.task.get('priority', 'Unassigned'))
        layout.addWidget(self.priority_input)
        layout.addWidget(QLabel("Notes:"))
        self.notes_input = QTextEdit()
        self.notes_input.setMaximumHeight(80)
        if self.task:
            self.notes_input.setPlainText(self.task.get('notes', ''))
        layout.addWidget(self.notes_input)
        layout.addWidget(QLabel("Status:"))
        self.status_input = QComboBox()
        self.status_input.addItems(['Not Started', 'In Progress', 'Hold', 'Completed', 'Archive this task'])
        if self.task:
            self.status_input.setCurrentText(self.task.get('status', 'In Progress'))
        layout.addWidget(self.status_input)
        layout.addWidget(QLabel("Start Date:"))
        self.start_date_input = QDateEdit()
        self.start_date_input.setCalendarPopup(True)
        if self.task:
            try:
                self.start_date_input.setDate(QDate.fromString(self.task.get('startDate', ''), Qt.ISODate))
            except:
                self.start_date_input.setDate(QDate.currentDate())
        else:
            self.start_date_input.setDate(QDate.currentDate())
        layout.addWidget(self.start_date_input)
        layout.addWidget(QLabel("Duration (Days):"))
        self.duration_input = QSpinBox()
        self.duration_input.setMinimum(1)
        self.duration_input.setMaximum(365)
        if self.task:
            self.duration_input.setValue(self.task.get('duration', 1))
        else:
            self.duration_input.setValue(1)
        layout.addWidget(self.duration_input)
        layout.addWidget(QLabel("Percent Complete (0-100):"))
        self.percent_input = QSpinBox()
        self.percent_input.setMinimum(0)
        self.percent_input.setMaximum(100)
        self.percent_input.valueChanged.connect(self.on_percent_changed)
        if self.task:
            self.percent_input.setValue(self.task.get('percent', 0))
        else:
            self.percent_input.setValue(0)
        layout.addWidget(self.percent_input)
        layout.addWidget(QLabel("If task due date has passed, please provide a reason:"))
        self.reason_input = QTextEdit()
        self.reason_input.setMaximumHeight(60)
        if self.task:
            self.reason_input.setPlainText(self.task.get('reasonForDelay', ''))
        layout.addWidget(self.reason_input)
        self.status_input.currentTextChanged.connect(self.on_status_changed)
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save Task")
        cancel_btn = QPushButton("Cancel")
        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    def on_status_changed(self, status):
        if status == 'Completed':
            self.percent_input.setValue(100)
        elif status == 'Archive this task':
            self.percent_input.setValue(0)
    def on_percent_changed(self, value):
        if value == 100:
            self.status_input.blockSignals(True)
            self.status_input.setCurrentText('Completed')
            self.status_input.blockSignals(False)
    def get_task_data(self):
        task = self.task_input.toPlainText()[:256]
        priority = self.priority_input.currentText()
        notes = self.notes_input.toPlainText()
        status = self.status_input.currentText()
        startDate = self.start_date_input.date().toString(Qt.ISODate)
        duration = self.duration_input.value()
        percent = self.percent_input.value()
        reasonForDelay = self.reason_input.toPlainText()
        lastUpdated = datetime.now().strftime('%Y-%m-%d')
        endDate = ''
        extendedDays = ''
        completedDate = ''
        archivedDate = ''
        if status == 'Completed':
            completedDate = datetime.now().strftime('%Y-%m-%d')
        if status == 'Archive this task':
            archivedDate = datetime.now().strftime('%Y-%m-%d')
        return {
            'task': task,
            'priority': priority,
            'notes': notes,
            'status': status,
            'startDate': startDate,
            'duration': duration,
            'percent': percent,
            'reasonForDelay': reasonForDelay,
            'lastUpdated': lastUpdated,
            'endDate': endDate,
            'extendedDays': extendedDays,
            'completedDate': completedDate,
            'archivedDate': archivedDate
        }

class PasswordSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Setup Password")
        self.setGeometry(100, 100, 400, 200)
        self.password = None
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("First Time Setup - Create Password"))
        layout.addWidget(QLabel("Password (min 4 characters):"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Confirm Password:"))
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.confirm_input)
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Create")
        ok_btn.clicked.connect(self.validate)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    def validate(self):
        pwd = self.password_input.text()
        confirm = self.confirm_input.text()
        if len(pwd) < 4:
            QMessageBox.warning(self, "Error", "Password must be at least 4 characters!")
            return
        if pwd != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
        self.password = pwd
        self.accept()
    def get_password(self):
        return self.password

class PasswordLoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.setGeometry(100, 100, 400, 180)
        self.password = None
        self.init_ui()
    def init_ui(self):
        layout = QVBoxLayout()
        self.msg_label = QLabel()
        self.msg_label.setStyleSheet("color: red")
        layout.addWidget(self.msg_label)
        layout.addWidget(QLabel("Enter your password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Unlock")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.password_input.setFocus()
    def get_password(self):
        return self.password_input.text()
    def show_invalid(self):
        self.msg_label.setText("Invalid password. Please try again..!")

class TodoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Task Progress Pad")
        self.setGeometry(50, 50, 1800, 900)
        self.tasks = []
        self.current_password = None
        self.selected_task_index = None
        self.config_dir = Path.home() / ".todoapp"
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "Tasks.json"
        self.init_ui()
        self.authenticate()
        self.last_activity = time.time()
        self.idle_timer = QTimer()
        self.idle_timer.timeout.connect(self.check_idle)
        self.idle_timer.start(1000)
        self.installEventFilter(self)
        for w in self.findChildren(QWidget):
            w.installEventFilter(self)
        self.autosave_timer = QTimer()
        self.autosave_timer.timeout.connect(self.autosave)
        self.autosave_timer.start(30000)
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        header_label = QLabel("Task Progress Pad")
        header_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(header_label)
        self.file_label = QLabel("Storage: Local | Encrypted | Protected")
        layout.addWidget(self.file_label)
        controls_layout = QHBoxLayout()
        self.add_btn = QPushButton("➕ Add Task")
        self.add_btn.clicked.connect(self.add_task)
        controls_layout.addWidget(self.add_btn)
        self.edit_btn = QPushButton("✏️ Edit Task")
        self.edit_btn.clicked.connect(self.edit_selected_task)
        controls_layout.addWidget(self.edit_btn)
        self.delete_btn = QPushButton("🗑️ Delete")
        self.delete_btn.clicked.connect(self.delete_selected)
        controls_layout.addWidget(self.delete_btn)
        self.save_btn = QPushButton("💾 Save Updates")
        self.save_btn.clicked.connect(self.save_updates)
        controls_layout.addWidget(self.save_btn)
        self.password_btn = QPushButton("🔑 Change Password")
        self.password_btn.clicked.connect(self.change_password)
        controls_layout.addWidget(self.password_btn)
        self.lock_btn = QPushButton("🔒 Lock")
        self.lock_btn.clicked.connect(self.lock_app)
        controls_layout.addWidget(self.lock_btn)
        controls_layout.addStretch()
        self.search_label = QLabel("🔍 Search Tasks:")
        controls_layout.addWidget(self.search_label)
        self.search_box = QLineEdit()
        self.search_box.setFixedWidth(250)
        self.search_box.returnPressed.connect(self.perform_search)
        controls_layout.addWidget(self.search_box)
        layout.addLayout(controls_layout)
        self.tabs = QTabWidget()
        self.active_table = QTableWidget()
        self.active_table.setColumnCount(12)
        self.active_table.setHorizontalHeaderLabels([
            'Select', 'Task', 'Priority', 'Notes', 'Status', 'Start Date',
            'Duration', 'Due Date', '% Complete', 'Last Updated', 'Extended Days', 'Reason for Delay'
        ])
        header = self.active_table.horizontalHeader()
        header.sectionClicked.connect(self.on_active_header_clicked)
        for i in range(self.active_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.active_table.setSelectionBehavior(self.active_table.SelectRows)
        self.active_table.setSelectionMode(self.active_table.MultiSelection)
        self.tabs.addTab(self.active_table, "Active (0)")
        self.completed_table = QTableWidget()
        self.completed_table.setColumnCount(6)
        self.completed_table.setHorizontalHeaderLabels([
            'Select', 'Task', 'Priority', 'Notes', 'Start Date', 'Completed Date'
        ])
        header2 = self.completed_table.horizontalHeader()
        header2.sectionClicked.connect(self.on_completed_header_clicked)
        for i in range(self.completed_table.columnCount()):
            header2.setSectionResizeMode(i, QHeaderView.Interactive)
        header2.setStretchLastSection(True)
        self.completed_table.setSelectionBehavior(self.completed_table.SelectRows)
        self.completed_table.setSelectionMode(self.completed_table.MultiSelection)
        self.tabs.addTab(self.completed_table, "Completed (0)")
        self.archived_table = QTableWidget()
        self.archived_table.setColumnCount(12)
        self.archived_table.setHorizontalHeaderLabels([
            'Select', 'Task', 'Priority', 'Notes', 'Status', 'Start Date',
            'Duration', 'Due Date', '% Complete', 'Last Updated', 'Extended Days', 'Reason for Delay'
        ])
        header3 = self.archived_table.horizontalHeader()
        header3.sectionClicked.connect(self.on_archived_header_clicked)
        for i in range(self.archived_table.columnCount()):
            header3.setSectionResizeMode(i, QHeaderView.Interactive)
        header3.setStretchLastSection(True)
        self.archived_table.setSelectionBehavior(self.archived_table.SelectRows)
        self.archived_table.setSelectionMode(self.archived_table.MultiSelection)
        self.tabs.addTab(self.archived_table, "Archived (0)")
        layout.addWidget(self.tabs)
        central_widget.setLayout(layout)
        self.lock_overlay = QWidget(self)
        self.lock_overlay.setStyleSheet("background-color: white;")
        self.lock_overlay.setGeometry(self.rect())
        self.lock_overlay.hide()
    def eventFilter(self, obj, event):
        if event.type() in (QEvent.MouseMove, QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.Wheel):
            self.last_activity = time.time()
        return False
    def check_idle(self):
        if time.time() - self.last_activity >= 600:
            self.trigger_lock()
    def trigger_lock(self):
        self.lock_overlay.show()
        dlg = PasswordLoginDialog(self)
        dlg.installEventFilter(self)
        for w in dlg.findChildren(QWidget):
            w.installEventFilter(self)
        dlg.installEventFilter(self)
        for w in dlg.findChildren(QWidget):
            w.installEventFilter(self)
        while True:
            if dlg.exec_() != QDialog.Accepted:
                continue
            pwd = dlg.get_password()
            if pwd == self.current_password:
                break
            dlg.show_invalid()
            dlg.password_input.clear()
        self.lock_overlay.hide()
        self.last_activity = time.time()
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'lock_overlay'):
            self.lock_overlay.setGeometry(self.rect())
    def on_active_header_clicked(self, idx):
        if idx == 2:
            order = ['High', 'Medium', 'Low', 'Unassigned']
            self.tasks = sorted(
                [t for t in self.tasks if t.get('status') not in ('Completed', 'Archive this task')],
                key=lambda t: order.index(t.get('priority', 'Unassigned'))
            ) + [
                t for t in self.tasks if t.get('status') in ('Completed', 'Archive this task')
            ]
        self.refresh_tables()
    def on_completed_header_clicked(self, idx):
        if idx == 2:
            order = ['High', 'Medium', 'Low', 'Unassigned']
            self.tasks = sorted(
                [t for t in self.tasks if t.get('status') == 'Completed'],
                key=lambda t: order.index(t.get('priority', 'Unassigned'))
            ) + [
                t for t in self.tasks if t.get('status') != 'Completed'
            ]
        self.refresh_tables()
    def on_archived_header_clicked(self, idx):
        if idx == 2:
            order = ['High', 'Medium', 'Low', 'Unassigned']
            self.tasks = sorted(
                [t for t in self.tasks if t.get('status') == 'Archive this task'],
                key=lambda t: order.index(t.get('priority', 'Unassigned'))
            ) + [
                t for t in self.tasks if t.get('status') != 'Archive this task'
            ]
        self.refresh_tables()
    def authenticate(self):
        if self.config_file.exists():
            dialog = PasswordLoginDialog(self)
            dialog.installEventFilter(self)
            for w in dialog.findChildren(QWidget):
                w.installEventFilter(self)
            dialog.installEventFilter(self)
            for w in dialog.findChildren(QWidget):
                w.installEventFilter(self)
            while True:
                if dialog.exec_() != QDialog.Accepted:
                    sys.exit()
                password = dialog.get_password()
                if self.load_from_storage_with_password(password):
                    self.current_password = password
                    self.refresh_tables()
                    break
                dialog.show_invalid()
                dialog.password_input.clear()
                continue
        else:
            dialog = PasswordSetupDialog(self)
            dialog.installEventFilter(self)
            for w in dialog.findChildren(QWidget):
                w.installEventFilter(self)
            dialog.installEventFilter(self)
            for w in dialog.findChildren(QWidget):
                w.installEventFilter(self)
            if dialog.exec_() != QDialog.Accepted:
                sys.exit()
            self.current_password = dialog.get_password()
            self.tasks = []
            self.save_to_storage()
    def load_from_storage_with_password(self, password):
        try:
            raw = Path(self.config_file).read_text().strip()
            if not raw:
                return False
            config_data = json.loads(raw)
            encrypted_data = config_data.get('tasks')
            if not encrypted_data:
                return False
            decrypted = EncryptionHandler.decrypt(encrypted_data, password)
            if not decrypted:
                return False
            loaded = json.loads(decrypted)
            if not isinstance(loaded, list):
                return False
            self.tasks = loaded
            return True
        except:
            return False
    def autosave(self):
        self.save_to_storage()
      
    def save_to_storage(self):
        if not self.current_password:
            return
        safe_ts = datetime.now().strftime('%d-%b-%Y %I.%M %p')
        backup_file = self.config_dir / f"Tasks Backup {safe_ts}.json"
        if self.config_file.exists():
            for f in self.config_dir.glob("Tasks Backup *.json"):
                f.unlink()
            self.config_file.rename(backup_file)
        encrypted_data = EncryptionHandler.encrypt(json.dumps(self.tasks), self.current_password)
        config_data = {
            'tasks': encrypted_data,
            'timestamp': datetime.now().isoformat()
        }
        Path(self.config_file).write_text(json.dumps(config_data))


    def save_updates(self):
        try:
            self.save_to_storage()
            QMessageBox.information(self, "Success", "Updates saved to local storage!")
        except:
            QMessageBox.warning(self, "Error", "Failed to save.")
    def add_task(self):
        dialog = TaskDialog(self)
        dialog.installEventFilter(self)
        for w in dialog.findChildren(QWidget):
            w.installEventFilter(self)
        dialog.installEventFilter(self)
        for w in dialog.findChildren(QWidget):
            w.installEventFilter(self)
        if dialog.exec_() == QDialog.Accepted:
            task_data = dialog.get_task_data()
            if task_data['percent'] == 100:
                task_data['status'] = 'Completed'
                task_data['completedDate'] = datetime.now().strftime('%Y-%m-%d')
            self.tasks.append(task_data)
            self.refresh_tables()
    def edit_selected_task(self):
        currtab = self.tabs.currentIndex()
        if currtab == 0:
            table = self.active_table
            tabletype = 'active'
        elif currtab == 1:
            table = self.completed_table
            tabletype = 'completed'
        else:
            table = self.archived_table
            tabletype = 'archived'
        selected = table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a task to edit.")
            return
        if len(selected) != 1:
            QMessageBox.warning(self, "Warning", "Please select only one task to edit.")
            return
        row = selected[0].row()
        taskindex = self.get_task_index_from_row(row, tabletype)
        if taskindex is not None and taskindex >= 0:
            try:
                self.edit_task(taskindex)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"An error occurred while editing: {str(e)}")
                return
    def edit_task(self, index):
        if not (0 <= index < len(self.tasks)):
            return
        oldstatus = self.tasks[index].get('status')
        dialog = TaskDialog(self, self.tasks[index])
        dialog.installEventFilter(self)
        for w in dialog.findChildren(QWidget):
            w.installEventFilter(self)
        if dialog.exec_() == QDialog.Accepted:
            updated = dialog.get_task_data()
            movetocompleted = updated['status'] == 'Completed' or updated['percent'] == 100
            movetoarchived = updated['status'] == 'Archive this task'
            if movetocompleted:
                updated['status'] = 'Completed'
                updated['completedDate'] = datetime.now().strftime('%Y-%m-%d')
                updated['archivedDate'] = ''
            elif movetoarchived:
                updated['archivedDate'] = datetime.now().strftime('%Y-%m-%d')
                updated['completedDate'] = ''
            else:
                updated['archivedDate'] = ''
            if updated['percent'] == 100:
                updated['status'] = 'Completed'
                updated['completedDate'] = datetime.now().strftime('%Y-%m-%d')
            else:
                updated['completedDate'] = ''
            if oldstatus == 'Archive this task':
                if movetoarchived:
                    pass
                elif movetocompleted:
                    updated['status'] = 'Completed'
                    updated['archivedDate'] = ''
                    updated['completedDate'] = datetime.now().strftime('%Y-%m-%d')
                else:
                    updated['archivedDate'] = ''
                    updated['completedDate'] = ''
            if updated['status'] == 'Completed':
                updated['completedDate'] = datetime.now().strftime('%Y-%m-%d')
            elif oldstatus == 'Completed':
                if movetoarchived:
                    updated['archivedDate'] = datetime.now().strftime('%Y-%m-%d')
                    updated['completedDate'] = ''
                elif not movetocompleted:
                    updated['completedDate'] = ''
            self.tasks[index] = updated
            self.refresh_tables()
    def delete_selected(self):
        active_selected = self.active_table.selectionModel().selectedRows()
        completed_selected = self.completed_table.selectionModel().selectedRows()
        archived_selected = self.archived_table.selectionModel().selectedRows()
        if not active_selected and not completed_selected and not archived_selected:
            QMessageBox.warning(self, "Warning", "Please select tasks to delete.")
            return
        total_selected = len(active_selected) + len(completed_selected) + len(archived_selected)
        if QMessageBox.question(self, "Confirm", f"Delete {total_selected} tasks?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            indices_to_delete = set()
            for row in active_selected:
                indices_to_delete.add(self.get_task_index_from_row(row.row(), 'active'))
            for row in completed_selected:
                indices_to_delete.add(self.get_task_index_from_row(row.row(), 'completed'))
            for row in archived_selected:
                indices_to_delete.add(self.get_task_index_from_row(row.row(), 'archived'))
            for idx in sorted([i for i in indices_to_delete if i is not None and i >= 0], reverse=True):
                self.tasks.pop(idx)
            self.refresh_tables()
    def get_task_index_from_row(self, row, table_type):
        table = None
        if table_type == 'active':
            table = self.active_table
        elif table_type == 'completed':
            table = self.completed_table
        elif table_type == 'archived':
            table = self.archived_table
        if table is not None:
            item = table.item(row, 1)
            if item is not None:
                idxdata = item.data(Qt.UserRole)
                if isinstance(idxdata, int):
                    return idxdata
        task_count = 0
        for idx, task in enumerate(self.tasks):
            status = task.get('status')
            if table_type == 'active' and status != 'Completed' and status != 'Archive this task':
                if task_count == row:
                    return idx
                task_count += 1
            elif table_type == 'completed' and status == 'Completed':
                if task_count == row:
                    return idx
                task_count += 1
            elif table_type == 'archived' and status == 'Archive this task':
                if task_count == row:
                    return idx
                task_count += 1
        return None
    def on_checkbox_state_changed(self, state, row, table):
        sel_model = table.selectionModel()
        index = table.model().index(row, 0)
        if state == Qt.Checked:
            sel_model.select(index, QItemSelectionModel.Select | QItemSelectionModel.Rows)
        else:
            sel_model.select(index, QItemSelectionModel.Deselect | QItemSelectionModel.Rows)
    def refresh_tables(self):
        self.active_table.setRowCount(0)
        self.completed_table.setRowCount(0)
        self.archived_table.setRowCount(0)
        active_count = 0
        completed_count = 0
        archived_count = 0
        for idx, task in enumerate(self.tasks):
            try:
                start_date = datetime.strptime(task.get('startDate', ''), '%Y-%m-%d')
                end_date = start_date + timedelta(days=int(task.get('duration', 0) or 0))
                task['endDate'] = end_date.strftime('%Y-%m-%d')
                diff = (datetime.now() - end_date).days
                task['extendedDays'] = diff if diff > 0 else ''
            except:
                task['endDate'] = ''
                task['extendedDays'] = ''
            status = task.get('status')
            if status == 'Completed':
                self.add_to_completed_table(idx, task)
                completed_count += 1
            elif status == 'Archive this task':
                self.add_to_archived_table(idx, task)
                archived_count += 1
            else:
                self.add_to_active_table(idx, task)
                active_count += 1
        self.tabs.setTabText(0, f"Active ({active_count})")
        self.tabs.setTabText(1, f"Completed ({completed_count})")
        self.tabs.setTabText(2, f"Archived ({archived_count})")
        if self.current_password:
            self.save_to_storage()
    def add_to_active_table(self, idx, task):
        row = self.active_table.rowCount()
        self.active_table.insertRow(row)
        checkbox = QCheckBox()
        checkbox_container = QWidget()
        box_layout = QHBoxLayout(checkbox_container)
        box_layout.setContentsMargins(0,0,0,0)
        box_layout.addStretch()
        box_layout.addWidget(checkbox)
        box_layout.addStretch()
        self.active_table.setCellWidget(row, 0, checkbox_container)
        checkbox.stateChanged.connect(lambda s, r=row, t=self.active_table: self.on_checkbox_state_changed(s, r, t))
        item_task = QTableWidgetItem(task.get('task',''))
        item_task.setData(Qt.UserRole, idx)
        self.active_table.setItem(row, 1, item_task)
        priority_item = QTableWidgetItem(task.get('priority',''))
        pmap = {'Low': QColor(139,195,74),'Medium': QColor(255,152,0),'High': QColor(244,67,54),'Unassigned': QColor(158,158,158)}
        if task.get('priority') in pmap:
            priority_item.setBackground(pmap[task.get('priority')])
            priority_item.setForeground(QColor(255,255,255))
        self.active_table.setItem(row, 2, priority_item)
        self.active_table.setItem(row, 3, QTableWidgetItem(task.get('notes','')))
        status_item = QTableWidgetItem(task.get('status',''))
        smap = {'Not Started': QColor(185,164,239),'In Progress': QColor(33,150,243),'Hold': QColor(255,152,0),'Completed': QColor(76,175,80),'Archive this task': QColor(158,158,158)}
        if task.get('status') in smap:
            status_item.setBackground(smap[task.get('status')])
            status_item.setForeground(QColor(255,255,255))
        self.active_table.setItem(row, 4, status_item)
        self.active_table.setItem(row, 5, QTableWidgetItem(task.get('startDate','')))
        ddisp = f"{task.get('duration')}d" if task.get('duration') else ''
        self.active_table.setItem(row, 6, QTableWidgetItem(ddisp))
        self.active_table.setItem(row, 7, QTableWidgetItem(task.get('endDate','')))
        percent_bar = QProgressBar()
        percent_bar.setMinimum(0)
        percent_bar.setMaximum(100)
        percent_bar.setValue(task.get('percent', 0))
        percent_bar.setFormat(f"{task.get('percent', 0)}%")
        percent_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bbb;
                background: #eee;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #4caf50;
            }
        """)
        self.active_table.setCellWidget(row, 8, percent_bar)
        self.active_table.setItem(row, 9, QTableWidgetItem(task.get('lastUpdated','')))
        ext = QTableWidgetItem(f"{task.get('extendedDays')}d" if task.get('extendedDays') else '')
        if task.get('extendedDays'):
            ext.setForeground(QColor(244,67,54))
        self.active_table.setItem(row, 10, ext)
        self.active_table.setItem(row, 11, QTableWidgetItem(task.get('reasonForDelay', '')))
    def add_to_completed_table(self, idx, task):
        row = self.completed_table.rowCount()
        self.completed_table.insertRow(row)
        checkbox = QCheckBox()
        checkbox_container = QWidget()
        box_layout = QHBoxLayout(checkbox_container)
        box_layout.setContentsMargins(0,0,0,0)
        box_layout.addStretch()
        box_layout.addWidget(checkbox)
        box_layout.addStretch()
        self.completed_table.setCellWidget(row, 0, checkbox_container)
        checkbox.stateChanged.connect(lambda s, r=row, t=self.completed_table: self.on_checkbox_state_changed(s, r, t))
        item_task = QTableWidgetItem(task.get('task',''))
        item_task.setData(Qt.UserRole, idx)
        self.completed_table.setItem(row, 1, item_task)
        priority_item = QTableWidgetItem(task.get('priority',''))
        pmap = {'Low': QColor(139,195,74),'Medium': QColor(255,152,0),'High': QColor(244,67,54),'Unassigned': QColor(158,158,158)}
        if task.get('priority') in pmap:
            priority_item.setBackground(pmap[task.get('priority')])
            priority_item.setForeground(QColor(255,255,255))
        self.completed_table.setItem(row, 2, priority_item)
        self.completed_table.setItem(row, 3, QTableWidgetItem(task.get('notes','')))
        self.completed_table.setItem(row, 4, QTableWidgetItem(task.get('startDate','')))
        self.completed_table.setItem(row, 5, QTableWidgetItem(task.get('completedDate','')))
    def add_to_archived_table(self, idx, task):
        row = self.archived_table.rowCount()
        self.archived_table.insertRow(row)
        checkbox = QCheckBox()
        checkbox_container = QWidget()
        box_layout = QHBoxLayout(checkbox_container)
        box_layout.setContentsMargins(0,0,0,0)
        box_layout.addStretch()
        box_layout.addWidget(checkbox)
        box_layout.addStretch()
        self.archived_table.setCellWidget(row, 0, checkbox_container)
        checkbox.stateChanged.connect(lambda s, r=row, t=self.archived_table: self.on_checkbox_state_changed(s, r, t))
        item_task = QTableWidgetItem(task.get('task',''))
        item_task.setData(Qt.UserRole, idx)
        self.archived_table.setItem(row, 1, item_task)
        priority_item = QTableWidgetItem(task.get('priority',''))
        pmap = {'Low': QColor(139,195,74),'Medium': QColor(255,152,0),'High': QColor(244,67,54),'Unassigned': QColor(158,158,158)}
        if task.get('priority') in pmap:
            priority_item.setBackground(pmap[task.get('priority')])
            priority_item.setForeground(QColor(255,255,255))
        self.archived_table.setItem(row, 2, priority_item)
        self.archived_table.setItem(row, 3, QTableWidgetItem(task.get('notes','')))
        status_item = QTableWidgetItem(task.get('status',''))
        status_item.setBackground(QColor(158,158,158))
        status_item.setForeground(QColor(255,255,255))
        self.archived_table.setItem(row, 4, status_item)
        self.archived_table.setItem(row, 5, QTableWidgetItem(task.get('startDate','')))
        ddisp = f"{task.get('duration')}d" if task.get('duration') else ''
        self.archived_table.setItem(row, 6, QTableWidgetItem(ddisp))
        self.archived_table.setItem(row, 7, QTableWidgetItem(task.get('endDate','')))
        percent_bar = QProgressBar()
        percent_bar.setMinimum(0)
        percent_bar.setMaximum(100)
        percent_bar.setValue(task.get('percent', 0))
        percent_bar.setFormat(f"{task.get('percent', 0)}%")
        percent_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bbb;
                background: #eee;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #4caf50;
            }
        """)
        self.archived_table.setCellWidget(row, 8, percent_bar)
        self.archived_table.setItem(row, 9, QTableWidgetItem(task.get('lastUpdated','')))
        ext = QTableWidgetItem(f"{task.get('extendedDays')}d" if task.get('extendedDays') else '')
        if task.get('extendedDays'):
            ext.setForeground(QColor(244,67,54))
        self.archived_table.setItem(row, 10, ext)
        self.archived_table.setItem(row, 11, QTableWidgetItem(task.get('reasonForDelay', '')))
    def change_password(self):
        new_pwd, ok1 = QInputDialog.getText(self, "New Password", "Enter new password (min 4):", QLineEdit.Password)
        if ok1 and len(new_pwd) >= 4:
            confirm_pwd, ok2 = QInputDialog.getText(self, "Confirm", "Confirm password:", QLineEdit.Password)
            if ok2:
                if new_pwd == confirm_pwd:
                    self.current_password = new_pwd
                    self.save_to_storage()
                    QMessageBox.information(self, "Success", "Password changed!")
                else:
                    QMessageBox.warning(self, "Error", "Passwords don't match!")
    def lock_app(self):
        self.save_to_storage()
        self.trigger_lock()
    def perform_search(self):
        text = self.search_box.text().strip().lower()
        if not text:
            self.refresh_tables()
            return
        results = []
        for idx, task in enumerate(self.tasks):
            for v in task.values():
                if isinstance(v, (str, int, float)):
                    if text in str(v).lower():
                        results.append((idx, task))
                        break
        self.active_table.setRowCount(0)
        self.completed_table.setRowCount(0)
        self.archived_table.setRowCount(0)
        a = c = r = 0
        for idx, task in results:
            status = task.get('status')
            if status == 'Completed':
                self.add_to_completed_table(idx, task)
                c += 1
            elif status == 'Archive this task':
                self.add_to_archived_table(idx, task)
                r += 1
            else:
                self.add_to_active_table(idx, task)
                a += 1
        self.tabs.setTabText(0, f"Active ({a})")
        self.tabs.setTabText(1, f"Completed ({c})")
        self.tabs.setTabText(2, f"Archived ({r})")

def main():
    import sys, os
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(base_path, "Todo_app.ico")
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(icon_path))
    window = TodoApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
