import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import string
import time

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        vscroll = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        hscroll = ttk.Scrollbar(self, orient="horizontal", command=canvas.xview)
        self.scrollable_frame = ttk.Frame(canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")
        hscroll.pack(side="bottom", fill="x")

def make_copyable_widget(widget):
    # Улучшенная функция для поддержки горячих клавиш в любой раскладке
    def do_copy(event=None):
        try:
            widget.clipboard_clear()
            # Для Entry
            if isinstance(widget, tk.Entry):
                if widget.selection_present():
                    sel = widget.selection_get()
                else:
                    sel = widget.get()
            # Для Text/ScrolledText
            else:
                try:
                    sel = widget.get("sel.first", "sel.last")
                except Exception:
                    # Если нет выделения, копируем весь текст
                    sel = widget.get(1.0, tk.END)
            widget.clipboard_append(sel)
        except Exception as e:
            print(f"Copy error: {e}")
        return "break"
    
    def do_paste(event=None):
        try:
            # Только для редактируемых виджетов
            if isinstance(widget, tk.Entry) and widget['state'] == 'normal':
                # Удаляем выделенный текст если есть
                if widget.selection_present():
                    widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
                # Вставляем из буфера
                txt = widget.clipboard_get()
                widget.insert(tk.INSERT, txt)
            elif hasattr(widget, 'get') and widget['state'] == 'normal':
                # Для Text виджетов
                if widget.tag_ranges(tk.SEL):
                    widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
                txt = widget.clipboard_get()
                widget.insert(tk.INSERT, txt)
        except Exception as e:
            print(f"Paste error: {e}")
        return "break"
    
    def do_select_all(event=None):
        try:
            if isinstance(widget, tk.Entry):
                widget.select_range(0, tk.END)
            else:
                widget.tag_add(tk.SEL, "1.0", tk.END)
                widget.mark_set(tk.INSERT, "1.0")
                widget.see(tk.INSERT)
        except Exception:
            pass
        return "break"
    
    # Создаем контекстное меню
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Копировать", command=do_copy, accelerator="Ctrl+C")
    menu.add_command(label="Вставить", command=do_paste, accelerator="Ctrl+V")
    menu.add_separator()
    menu.add_command(label="Выделить все", command=do_select_all, accelerator="Ctrl+A")
    
    def show_menu(event):
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def on_key_press(event):
        # Обработка горячих клавиш независимо от раскладки
        # Проверяем состояние Control
        if event.state & 0x4:  # Control нажат
            # Используем keycode для определения нажатой клавиши
            # keycode не зависит от раскладки
            if event.keycode == 67 or event.char == 'с':  # C или С (англ/рус)
                return do_copy()
            elif event.keycode == 86 or event.char == 'м':  # V или М (англ/рус)
                return do_paste()
            elif event.keycode == 65 or event.char == 'ф':  # A или Ф (англ/рус)
                return do_select_all()
    
    # Привязываем обработчик к событию нажатия клавиши
    widget.bind("<KeyPress>", on_key_press)
    
    # Контекстное меню по правой кнопке мыши
    widget.bind("<Button-3>", show_menu)
    
    # Для виджетов в состоянии disabled разрешаем фокус для копирования
    if hasattr(widget, 'get'):
        widget.bind("<FocusIn>", lambda e: widget.configure(takefocus=True))

class ReadonlyText(scrolledtext.ScrolledText):
    """Кастомный ScrolledText с поддержкой копирования в режиме readonly"""
    def __init__(self, *args, **kwargs):
        kwargs['state'] = 'disabled'
        super().__init__(*args, **kwargs)
        make_copyable_widget(self)
    
    def set_text(self, text):
        """Безопасная установка текста"""
        self.config(state='normal')
        self.delete(1.0, tk.END)
        self.insert(1.0, text)
        self.config(state='disabled')

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Генератор паролей")
        self.root.geometry("900x950")
        self.MIN_LENGTH = 1
        self.MAX_LENGTH = 64
        self.length_var = tk.StringVar(value="8")
        self.latin_lower_var = tk.BooleanVar(value=True)
        self.russian_lower_var = tk.BooleanVar(value=False)
        self.digits_var = tk.BooleanVar(value=True)
        self.case_sensitive_var = tk.BooleanVar(value=False)
        self.special_chars_var = tk.StringVar(value="")
        self.require_digit = tk.BooleanVar(value=False)
        self.require_lowercase = tk.BooleanVar(value=False)
        self.require_uppercase = tk.BooleanVar(value=False)
        self.require_special = tk.BooleanVar(value=False)
        self.excluded_chars = set()

        self.main_scroll = ScrollableFrame(self.root)
        self.main_scroll.pack(fill="both", expand=True)
        self.create_widgets(self.main_scroll.scrollable_frame)
        self.update_password()

    def create_widgets(self, root_place):
        notebook = ttk.Notebook(root_place)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        generation_frame = tk.Frame(notebook)
        notebook.add(generation_frame, text="Генерация пароля")
        self.create_generation_tab(generation_frame)
        validation_frame = tk.Frame(notebook)
        notebook.add(validation_frame, text="Проверка пароля")
        self.create_validation_tab(validation_frame)
        exclusion_frame = tk.Frame(notebook)
        notebook.add(exclusion_frame, text="Исключение символов")
        self.create_exclusion_tab(exclusion_frame)

    def create_generation_tab(self, parent):
        title = tk.Label(parent, text="Генератор паролей", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        params_frame = tk.LabelFrame(parent, text="Параметры пароля", padx=20, pady=20)
        params_frame.pack(padx=20, pady=10, fill="both", expand=True)
        length_frame = tk.Frame(params_frame)
        length_frame.pack(fill="x", pady=5)
        tk.Label(length_frame, text=f"Длина пароля ({self.MIN_LENGTH}-{self.MAX_LENGTH}):", width=30, anchor="w").pack(side="left")
        self.length_entry = tk.Entry(length_frame, textvariable=self.length_var, width=10)
        self.length_entry.pack(side="left")
        self.length_entry.bind("<KeyRelease>", lambda e: self.validate_length_on_input())
        self.length_entry.bind("<FocusOut>", lambda e: self.validate_length_strict())
        make_copyable_widget(self.length_entry)
        length_hint = tk.Label(params_frame, text=f"Минимальное значение: {self.MIN_LENGTH}, Максимальное значение: {self.MAX_LENGTH}", font=("Arial", 8), fg="gray")
        length_hint.pack(anchor="w", padx=5)
        latin_lower_check = tk.Checkbutton(params_frame, text="Строчные латинские буквы (a-z)", variable=self.latin_lower_var, command=self.update_password)
        latin_lower_check.pack(anchor="w", pady=5)
        russian_lower_check = tk.Checkbutton(params_frame, text="Строчные русские буквы (а-я)", variable=self.russian_lower_var, command=self.update_password)
        russian_lower_check.pack(anchor="w", pady=5)
        digits_check = tk.Checkbutton(params_frame, text="Цифры (0-9)", variable=self.digits_var, command=self.update_password)
        digits_check.pack(anchor="w", pady=5)
        case_check = tk.Checkbutton(params_frame, text="Учитывать регистр (использовать заглавные буквы)", variable=self.case_sensitive_var, command=self.update_password)
        case_check.pack(anchor="w", pady=5)
        special_frame = tk.Frame(params_frame)
        special_frame.pack(fill="x", pady=5)
        tk.Label(special_frame, text="Дополнительные символы:", width=30, anchor="w").pack(side="left")
        self.special_entry = tk.Entry(special_frame, textvariable=self.special_chars_var, width=20)
        self.special_entry.pack(side="left")
        self.special_entry.bind("<KeyRelease>", lambda e: self.validate_and_update_special_chars())
        make_copyable_widget(self.special_entry)
        hint_label = tk.Label(params_frame, text="Введите дополнительные символы (например: !@#$%)", font=("Arial", 8), fg="gray")
        hint_label.pack(anchor="w", padx=5)
        ttk.Separator(params_frame, orient="horizontal").pack(fill="x", pady=10)
        constraints_label = tk.Label(params_frame, text="Обязательные требования:", font=("Arial", 10, "bold"))
        constraints_label.pack(anchor="w", pady=5)
        tk.Checkbutton(params_frame, text="Хотя бы одна цифра", variable=self.require_digit, command=self.update_password).pack(anchor="w", pady=2)
        tk.Checkbutton(params_frame, text="Хотя бы одна строчная латинская буква", variable=self.require_lowercase, command=self.update_password).pack(anchor="w", pady=2)
        tk.Checkbutton(params_frame, text="Хотя бы одна заглавная латинская буква", variable=self.require_uppercase, command=self.update_password).pack(anchor="w", pady=2)
        tk.Checkbutton(params_frame, text="Хотя бы один спецсимвол", variable=self.require_special, command=self.update_password).pack(anchor="w", pady=2)
        ttk.Separator(params_frame, orient="horizontal").pack(fill="x", pady=10)
        alphabet_frame = tk.Frame(params_frame)
        alphabet_frame.pack(fill="x", pady=5)
        tk.Label(alphabet_frame, text="Итоговый алфавит:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.alphabet_text = ReadonlyText(alphabet_frame, height=3, wrap="none")
        self.alphabet_text.pack(fill="both", pady=5)
        size_frame = tk.Frame(params_frame)
        size_frame.pack(fill="x", pady=5)
        tk.Label(size_frame, text="Размер алфавита:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.alphabet_size_label = tk.Label(size_frame, text="0", font=("Arial", 12), fg="green")
        self.alphabet_size_label.pack(anchor="w")
        excluded_info_frame = tk.Frame(params_frame)
        excluded_info_frame.pack(fill="x", pady=5)
        tk.Label(excluded_info_frame, text="Исключено символов:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.excluded_count_label = tk.Label(excluded_info_frame, text="0", font=("Arial", 12), fg="red")
        self.excluded_count_label.pack(anchor="w")
        count_frame = tk.Frame(params_frame)
        count_frame.pack(fill="x", pady=5)
        tk.Label(count_frame, text="Количество возможных паролей:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.count_label = tk.Label(count_frame, text="0", font=("Arial", 12), fg="blue")
        self.count_label.pack(anchor="w")
        time_frame = tk.Frame(params_frame)
        time_frame.pack(fill="x", pady=5)
        tk.Label(time_frame, text="Время генерации пароля:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.generation_time_label = tk.Label(time_frame, text="0.000000 сек", font=("Arial", 12), fg="purple")
        self.generation_time_label.pack(anchor="w")
        self.performance_label = tk.Label(params_frame, text="", font=("Arial", 8, "italic"), fg="gray")
        self.performance_label.pack(anchor="w", padx=5)
        password_frame = tk.Frame(params_frame)
        password_frame.pack(fill="x", pady=5)
        tk.Label(password_frame, text="Сгенерированный пароль:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.password_text = ReadonlyText(password_frame, height=2, wrap="none", font=("Arial", 12))
        self.password_text.pack(fill="both", pady=5)
        update_button = tk.Button(params_frame, text="Обновить пароль", command=self.update_password, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), padx=20, pady=10)
        update_button.pack(pady=10)

    def create_validation_tab(self, parent):
        title = tk.Label(parent, text="Проверка пароля", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        check_frame = tk.LabelFrame(parent, text="Введите пароль для проверки", padx=20, pady=20)
        check_frame.pack(padx=20, pady=10, fill="both", expand=True)
        tk.Label(check_frame, text="Пароль для проверки:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.check_password_entry = tk.Entry(check_frame, font=("Arial", 12), width=40)
        self.check_password_entry.pack(fill="x", pady=5)
        make_copyable_widget(self.check_password_entry)
        check_button = tk.Button(check_frame, text="Проверить пароль", command=self.check_password, bg="#2196F3", fg="white", font=("Arial", 12, "bold"), padx=20, pady=10)
        check_button.pack(pady=10)
        result_frame = tk.LabelFrame(check_frame, text="Результат проверки", padx=10, pady=10)
        result_frame.pack(fill="both", expand=True, pady=10)
        self.check_result_text = ReadonlyText(result_frame, height=15, wrap="none", font=("Arial", 10))
        self.check_result_text.pack(fill="both", expand=True)

    def create_exclusion_tab(self, parent):
        title = tk.Label(parent, text="Исключение символов из алфавита", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        exclusion_frame = tk.LabelFrame(parent, text="Управление исключениями", padx=20, pady=20)
        exclusion_frame.pack(padx=20, pady=10, fill="both", expand=True)
        instruction = tk.Label(exclusion_frame, text="Введите символы, которые НЕ должны использоваться в пароле.\nЭти символы будут исключены из алфавита и не будут учитываться при генерации.", font=("Arial", 9), justify="left", fg="blue")
        instruction.pack(anchor="w", pady=5)
        tk.Label(exclusion_frame, text="Символы для исключения:", font=("Arial", 10, "bold")).pack(anchor="w", pady=5)
        self.exclusion_entry = tk.Entry(exclusion_frame, font=("Arial", 12), width=50)
        self.exclusion_entry.pack(fill="x", pady=5)
        make_copyable_widget(self.exclusion_entry)
        button_frame = tk.Frame(exclusion_frame)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Применить исключения", command=self.apply_exclusions, bg="#FF9800", fg="white", font=("Arial", 11, "bold"), padx=15, pady=8).pack(side="left", padx=5)
        tk.Button(button_frame, text="Очистить исключения", command=self.clear_exclusions, bg="#F44336", fg="white", font=("Arial", 11, "bold"), padx=15, pady=8).pack(side="left", padx=5)
        tk.Label(exclusion_frame, text="Текущие исключенные символы:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(10, 5))
        self.excluded_display = ReadonlyText(exclusion_frame, height=3, wrap="none", font=("Arial", 11))
        self.excluded_display.pack(fill="both", pady=5)
        example_frame = tk.LabelFrame(exclusion_frame, text="Примеры", padx=10, pady=10)
        example_frame.pack(fill="x", pady=10)
        examples = [
            "• Исключить похожие символы: 0O1lI",
            "• Исключить специальные символы: !@#$%",
            "• Исключить определенные буквы: aeiou",
        ]
        for example in examples:
            tk.Label(example_frame, text=example, font=("Arial", 9), anchor="w").pack(anchor="w")

    def apply_exclusions(self):
        exclusion_text = self.exclusion_entry.get()
        self.excluded_chars = set(exclusion_text)
        self.excluded_display.set_text(''.join(sorted(self.excluded_chars)) if self.excluded_chars else "Нет исключенных символов")
        messagebox.showinfo("Исключения применены", f"Исключено символов: {len(self.excluded_chars)}\n\nСимволы: {''.join(sorted(self.excluded_chars)) if self.excluded_chars else 'нет'}")
        self.update_password()

    def clear_exclusions(self):
        self.excluded_chars.clear()
        self.exclusion_entry.delete(0, tk.END)
        self.excluded_display.set_text("Нет исключенных символов")
        messagebox.showinfo("Исключения очищены", "Все исключения символов были удалены.")
        self.update_password()

    def check_password(self):
        password = self.check_password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для проверки!")
            return
        alphabet = self.get_alphabet()
        length = len(password)
        results = []
        results.append("=" * 50)
        results.append(f"ПРОВЕРКА ПАРОЛЯ: {password}")
        results.append("=" * 50)
        results.append("")
        results.append(f"1. ПРОВЕРКА ДЛИНЫ:")
        results.append(f"   Длина пароля: {length}")
        results.append(f"   Допустимый диапазон: {self.MIN_LENGTH}-{self.MAX_LENGTH}")
        if self.MIN_LENGTH <= length <= self.MAX_LENGTH:
            results.append("   ✓ Длина соответствует требованиям")
        else:
            results.append("   ✗ Длина НЕ соответствует требованиям!")
        results.append("")
        results.append(f"2. ПРОВЕРКА СИМВОЛОВ:")
        invalid_chars = []
        for char in password:
            if char not in alphabet:
                invalid_chars.append(char)
        if not invalid_chars:
            results.append("   ✓ Все символы из допустимого алфавита")
        else:
            results.append(f"   ✗ Обнаружены недопустимые символы: {''.join(set(invalid_chars))}")
        results.append("")
        results.append(f"3. ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ТРЕБОВАНИЙ:")
        all_requirements_met = True
        if self.require_digit.get():
            has_digit = any(c.isdigit() for c in password)
            if has_digit:
                results.append("   ✓ Содержит хотя бы одну цифру")
            else:
                results.append("   ✗ НЕ содержит цифру (требуется)")
                all_requirements_met = False
        if self.require_lowercase.get():
            has_lowercase = any(c in string.ascii_lowercase for c in password)
            if has_lowercase:
                results.append("   ✓ Содержит хотя бы одну строчную латинскую букву")
            else:
                results.append("   ✗ НЕ содержит строчную латинскую букву (требуется)")
                all_requirements_met = False
        if self.require_uppercase.get():
            has_uppercase = any(c in string.ascii_uppercase for c in password)
            if has_uppercase:
                results.append("   ✓ Содержит хотя бы одну заглавную латинскую букву")
            else:
                results.append("   ✗ НЕ содержит заглавную латинскую букву (требуется)")
                all_requirements_met = False
        if self.require_special.get():
            special_chars = self.special_chars_var.get()
            if special_chars:
                has_special = any(c in special_chars for c in password)
                if has_special:
                    results.append("   ✓ Содержит хотя бы один спецсимвол")
                else:
                    results.append("   ✗ НЕ содержит спецсимвол (требуется)")
                    all_requirements_met = False
        if not (self.require_digit.get() or self.require_lowercase.get() or self.require_uppercase.get() or self.require_special.get()):
            results.append("   (Обязательные требования не заданы)")
        results.append("")
        results.append(f"4. ПРОВЕРКА ИСКЛЮЧЕННЫХ СИМВОЛОВ:")
        excluded_found = []
        for char in password:
            if char in self.excluded_chars:
                excluded_found.append(char)
        if not excluded_found:
            results.append("   ✓ Не содержит исключенных символов")
        else:
            results.append(f"   ✗ Содержит исключенные символы: {''.join(set(excluded_found))}")
        results.append("")
        results.append("=" * 50)
        overall_valid = (self.MIN_LENGTH <= length <= self.MAX_LENGTH and not invalid_chars and all_requirements_met and not excluded_found)
        if overall_valid:
            results.append("ИТОГ: ✓ ПАРОЛЬ СООТВЕТСТВУЕТ ВСЕМ ТРЕБОВАНИЯМ")
        else:
            results.append("ИТОГ: ✗ ПАРОЛЬ НЕ СООТВЕТСТВУЕТ ТРЕБОВАНИЯМ")
        results.append("=" * 50)
        self.check_result_text.set_text("\n".join(results))

    def get_base_alphabet_chars(self):
        base_chars = set()
        if self.latin_lower_var.get():
            base_chars.update(string.ascii_lowercase)
            if self.case_sensitive_var.get():
                base_chars.update(string.ascii_uppercase)
        if self.russian_lower_var.get():
            base_chars.update("абвгдежзийклмнопрстуфхцчшщъыьэюя")
            if self.case_sensitive_var.get():
                base_chars.update("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
        if self.digits_var.get():
            base_chars.update(string.digits)
        return base_chars

    def validate_and_update_special_chars(self):
        special = self.special_chars_var.get()
        base_chars = self.get_base_alphabet_chars()
        duplicates = [char for char in special if char in base_chars]
        if duplicates:
            duplicate_str = ''.join(dict.fromkeys(duplicates))
            messagebox.showwarning(
                "Предупреждение о дублировании",
                f"Следующие символы уже присутствуют в базовом алфавите и будут проигнорированы:\n\n{duplicate_str}"
            )
            filtered_special = ''.join([char for char in special if char not in base_chars])
            self.special_chars_var.set(filtered_special)
            self.special_entry.config(fg="red")
            self.root.after(500, lambda: self.special_entry.config(fg="black"))
        self.update_password()

    def validate_length_on_input(self):
        try:
            value = self.length_var.get()
            if value == "":
                self.length_entry.config(bg="white")
                return
            length = int(value)
            if length < self.MIN_LENGTH or length > self.MAX_LENGTH:
                self.length_entry.config(bg="#ffcccc")
            else:
                self.length_entry.config(bg="#ccffcc")
                self.update_password()
        except ValueError:
            self.length_entry.config(bg="#ffcccc")

    def validate_length_strict(self):
        try:
            value = self.length_var.get()
            if value == "":
                messagebox.showerror(
                    "Ошибка ввода",
                    f"Длина пароля не может быть пустой!\n\nДопустимый диапазон: от {self.MIN_LENGTH} до {self.MAX_LENGTH}"
                )
                self.length_var.set("8")
                self.length_entry.config(bg="white")
                return False
            length = int(value)
            if length < self.MIN_LENGTH:
                messagebox.showerror(
                    "Граничное значение нарушено",
                    f"Длина пароля ({length}) меньше минимально допустимого значения!\n\nМинимальная длина: {self.MIN_LENGTH}\nЗначение будет установлено на {self.MIN_LENGTH}."
                )
                self.length_var.set(str(self.MIN_LENGTH))
                self.length_entry.config(bg="white")
                self.update_password()
                return False
            elif length > self.MAX_LENGTH:
                messagebox.showerror(
                    "Граничное значение нарушено",
                    f"Длина пароля ({length}) превышает максимально допустимое значение!\n\nМаксимальная длина: {self.MAX_LENGTH}\nЗначение будет установлено на {self.MAX_LENGTH}."
                )
                self.length_var.set(str(self.MAX_LENGTH))
                self.length_entry.config(bg="white")
                self.update_password()
                return False
            self.length_entry.config(bg="white")
            self.update_password()
            return True
        except ValueError:
            messagebox.showerror(
                "Ошибка типа данных",
                f"Длина пароля должна быть целым числом!\n\nДопустимый диапазон: от {self.MIN_LENGTH} до {self.MAX_LENGTH}"
            )
            self.length_var.set("8")
            self.length_entry.config(bg="white")
            return False

    def validate_length(self):
        try:
            length = int(self.length_var.get())
            if length < self.MIN_LENGTH or length > self.MAX_LENGTH:
                return False
            return True
        except ValueError:
            return False

    def get_alphabet(self):
        alphabet = ""
        if self.latin_lower_var.get():
            alphabet += string.ascii_lowercase
            if self.case_sensitive_var.get():
                alphabet += string.ascii_uppercase
        if self.russian_lower_var.get():
            alphabet += "абвгдежзийклмнопрстуфхцчшщъыьэюя"
            if self.case_sensitive_var.get():
                alphabet += "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        if self.digits_var.get():
            alphabet += string.digits
        special = self.special_chars_var.get()
        if special:
            for char in special:
                if char not in alphabet:
                    alphabet += char
        alphabet = ''.join([char for char in alphabet if char not in self.excluded_chars])
        return alphabet

    def calculate_password_count(self, alphabet_length, password_length):
        if alphabet_length == 0:
            return 0
        return alphabet_length ** password_length

    def generate_password(self, alphabet, length):
        if not alphabet or length < 1:
            return ""
        max_attempts = 1000
        for attempt in range(max_attempts):
            password = ''.join(random.choice(alphabet) for _ in range(length))
            if self.require_digit.get():
                if not any(c.isdigit() for c in password):
                    continue
            if self.require_lowercase.get():
                if not any(c in string.ascii_lowercase for c in password):
                    continue
            if self.require_uppercase.get():
                if not any(c in string.ascii_uppercase for c in password):
                    continue
            if self.require_special.get():
                special_chars = self.special_chars_var.get()
                if special_chars and not any(c in special_chars for c in password):
                    continue
            return password
        return ''.join(random.choice(alphabet) for _ in range(length))

    def update_password(self):
        if not self.validate_length():
            return
        alphabet = self.get_alphabet()
        try:
            length = int(self.length_var.get())
        except ValueError:
            length = 8
        if not alphabet:
            messagebox.showwarning("Предупреждение", "Выберите хотя бы один тип символов!")
            self.alphabet_text.set_text("")
            self.alphabet_size_label.config(text="0")
            self.excluded_count_label.config(text=str(len(self.excluded_chars)))
            self.count_label.config(text="0")
            self.generation_time_label.config(text="0.000000 сек")
            self.performance_label.config(text="")
            self.password_text.set_text("")
            return
        
        self.alphabet_text.set_text(alphabet)
        self.alphabet_size_label.config(text=str(len(alphabet)))
        self.excluded_count_label.config(text=str(len(self.excluded_chars)))
        count = self.calculate_password_count(len(alphabet), length)
        self.count_label.config(text=f"{count:,}".replace(",", " "))
        start_time = time.time()
        password = self.generate_password(alphabet, length)
        end_time = time.time()
        generation_time = end_time - start_time
        self.generation_time_label.config(text=f"{generation_time:.6f} сек")
        if generation_time < 1.0:
            perf_status = f"✓ Отличная производительность! Генерация заняла менее 1 секунды."
            perf_color = "darkgreen"
        else:
            perf_status = f"⚠ Генерация заняла более 1 секунды."
            perf_color = "red"
        self.performance_label.config(text=perf_status, fg=perf_color)
        self.password_text.set_text(password)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()