"""
ARM64 Assembly Code and Memory Simulator

本程序是一个轻量级的ARM64指令集解析和执行模拟器，设计用于解析从IDA Pro反汇编输出的ARM64代码，
保存于.s文件中。它允许用户通过模拟执行来分析寄存器的变化，帮助理解和分析LLVM生成的ARM64指令。
该模拟器是一个独立的工具，无需依赖Unicorn、unidbg或其他调试工具，适合用于快速理解和分析代码行为。

特性和优势：
    *轻量级和独立：不需要复杂的依赖或配置，可以在任何支持Python的环境中快速部署和运行。
    *直接解析IDA输出：直接处理IDA反汇编输出的.s文件，便于整合到现有的分析工作流中。
    *详细的执行跟踪：在执行每条指令时输出寄存器和内存状态变化，详细记录指令执行过程。
    *支持单步和连续执行：用户可以选择单步执行来详细观察每个操作的影响，或连续执行以快速遍历代码段。
    *寄存器和内存状态模拟：模拟寄存器和内存的读写操作，提供对ARM64操作的深入理解。

使用场景：
    *教育和学习：理解和教学ARM64指令集结构及其在不同编译输出（如LLVM）中的应用。
    *快速原型和测试：在修改汇编代码前，快速模拟和测试指令效果，验证理论分析。
    *安全分析：分析潜在的安全漏洞，理解攻击载荷如何影响程序状态。
    *性能分析：分析代码如何操作寄存器和内存，帮助优化性能关键代码。

作者：c3VpZmUgQGdtYWlsIGRvdGNvbQ==
许可协议：MIT License
"""

import json
import ctypes


def read_file(filename):
    """
    读取指定文件的所有行，并返回一个包含这些行的列表。

    Args:
        filename (str): 要读取的文件名。

    Returns:
        list: 包含文件中所有行的列表，每行作为一个字符串元素。

    Raises:
        无。

    """
    lines = []
    try:
        with open(filename, encoding="utf-8") as f:
            for line in f:
                lines.append(line)
    except FileNotFoundError:
        print(f"文件 {filename} 未找到。")
    except Exception as e:
        print(f"发生错误: {e}")
    return lines


def clean_unicode_characters(s):
    """
    去除字符串中特定的Unicode字符。

    Args:
        s (str): 待处理的字符串。

    Returns:
        str: 处理后的字符串。

    """
    replacements = {"\u2026": "", "\u2191o": ""}
    for old, new in replacements.items():
        s = s.replace(old, new)
    return s.strip()


def parse_asm_line(line):
    """
    将汇编指令行解析为字典对象

    Args:
    line (str): 汇编指令行字符串

    Returns:
    dict: 包含地址、操作码十六进制、指令和注释的字典对象，若解析失败则返回 None

    """
    # 检查line长度，避免IndexError
    if len(line) < 36:
        return None

    address_part = line[0:24].split(":")
    if len(address_part) < 2:
        return None

    address = "0x" + address_part[1].strip()
    ophex = line[24:36].strip()
    if not ophex:
        return None

    comment = ""
    instruction_part = line[36:]
    if ";" in instruction_part:
        instruction, comment = instruction_part.split(";", 1)
    else:
        instruction = instruction_part

    if instruction == "":
        return None

    address = clean_unicode_characters(address)
    ophex = clean_unicode_characters(ophex)
    instruction = clean_unicode_characters(instruction)
    comment = clean_unicode_characters(comment)

    try:
        return {
            "address": int(address, 16),
            "ophex": ophex,
            "instruction": instruction,
            "comment": comment,
        }
    except ValueError:
        # 如果address无法转换为int，则返回None
        return None


def load_asm_code(lines):
    """
    将输入的汇编代码字符串列表解析为字典形式，其中键为地址，值为包含地址、指令和操作数的字典。

    Args:
        lines (List[str]): 汇编代码字符串列表。

    Returns:
        Dict[str, Dict[str, Union[str, List[str]]]]: 包含地址、指令和操作数的字典。

    """
    asm_code = {}
    for line in lines:
        parsed_line = parse_asm_line(line)
        if parsed_line:
            asm_code[parsed_line["address"]] = parsed_line
    return asm_code


def write_to_file(filename, data):
    """
    将数据写入到指定的json文件中

    Args:
        filename: str类型，json文件的路径
        data: dict类型，要写入到json文件中的数据

    Returns:
        None

    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def parse_memory_lines(lines):
    """
    解析内存行，将解析结果以字典形式返回。

    Args:
    - lines: 内存行列表，每个元素为字符串类型。

    Returns:
    - memory: 包含解析结果的字典，键为内存地址（整数类型），值为包含地址和函数名的字典（若函数名为空，则只有地址）或具体数值（整数或字符串类型）。

    """
    memory = {}

    for line in lines:
        if "DCB" in line:
            address = "0x" + line.split()[0].split(":")[1].strip()
            dcb = line.find("DCB")
            if "__objc_methname" in line:
                memory[line[0 : dcb - 1].split()[-1]] = {
                    "address": int(address, 16),
                    "methname": line[dcb + 4 :].split(";")[0].strip(),
                }
                continue

        if "DCQ" in line:
            address = "0x" + line.split()[0].split(":")[1].strip()
            dcq = line.find("DCQ")

            if "__objc_selrefs" in line:
                memory[line[0 : dcq - 1].split()[-1]] = {
                    "address": int(address, 16),
                    "methname": line[dcq + 4 :].split(";")[0].strip(),
                }
                continue
            data = (
                line[dcq + 4 :]
                .split(";")[0]
                .strip()
                .replace("sub_", "0x")
                .replace("loc_", "0x")
                .replace("off_", "0x")
            )
            memory[int(address, 16)] = int(data, 16) if data.startswith("0x") else data
    return memory


class ARM64Registers:
    def __init__(self):
        self.registers = [0] * 31
        self.sp = 0
        self.fp = 0
        self.lr = 0
        self.pc = 0
        self.nzcv = {"N": 0, "Z": 0, "C": 0, "V": 0}

    def set_register(self, reg_name, value):
        """
        设置CPU寄存器的值。

        Args:
            reg_name (str): 寄存器的名称，例如"X0"、"W1"、"SP"、"FP"、"LR"、"PC"或"NZCV"中的一位。
            value (int): 要设置的值。

        Returns:
            None

        Raises:
            ValueError: 如果寄存器名称或值无效。

        """
        try:
            if reg_name.startswith("X") and 0 <= int(reg_name[1:]) < 31:
                index = int(reg_name[1:])
                self.registers[index] = value & 0xFFFFFFFFFFFFFFFF
                if index == 29:
                    self.fp = value
            elif reg_name.startswith("W") and 0 <= int(reg_name[1:]) < 31:
                index = int(reg_name[1:])
                self.registers[index] = value & 0xFFFFFFFF
            elif reg_name == "SP":
                self.sp = value
            elif reg_name == "FP" and 0 <= int(reg_name[1:]) < 31:
                self.fp = value
                self.registers[29] = value
            elif reg_name == "LR":
                self.lr = value
            elif reg_name == "PC":
                self.pc = value
            elif reg_name in self.nzcv and isinstance(value, int) and value in (0, 1):
                self.nzcv[reg_name] = value
            else:
                raise ValueError("无效的寄存器名称或值。")
        except ValueError as e:
            print(f"错误: {e}")

    def get_register(self, reg_name):
        """
        获取指定名称的寄存器值。

        Args:
            reg_name (str): 寄存器的名称，如"X0"、"W15"、"SP"、"LR"、"PC"或"NZCV"中的标志位。

        Returns:
            int or None: 寄存器的值，如果寄存器名称无效则返回None。

        Raises:
            ValueError: 如果寄存器名称无效，则会引发此异常。

        """
        try:
            if reg_name.startswith("X") and 0 <= int(reg_name[1:]) < 31:
                return self.registers[int(reg_name[1:])]
            elif reg_name.startswith("W") and 0 <= int(reg_name[1:]) < 31:
                index = int(reg_name[1:])
                return self.registers[index] & 0xFFFFFFFF
            elif reg_name == "SP":
                return self.sp
            elif reg_name == "LR":
                return self.lr
            elif reg_name == "PC":
                return self.pc
            elif reg_name in self.nzcv:
                return self.nzcv[reg_name]
            else:
                raise ValueError("无效的寄存器名称。")
        except ValueError as e:
            print(f"错误: {e}")
            return None

    def check_condition(self, condition):
        """
        根据给定的条件检查NZCV标志位，并返回布尔值表示条件是否满足。

        Args:
            condition (str): 条件字符串，如'EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE'。

        Returns:
            bool: 如果条件满足，则返回True；否则返回False。

        """
        # 定义条件字典，键为条件字符串，值为条件判断逻辑
        conditions = {
            # 相等条件
            "EQ": self.nzcv["Z"] == 1,
            # 不相等条件
            "NE": self.nzcv["Z"] == 0,
            # 带有进位标志条件
            "CS": self.nzcv["C"] == 1,
            # 不带有进位标志条件
            "CC": self.nzcv["C"] == 0,
            # 负数条件
            "MI": self.nzcv["N"] == 1,
            # 正数条件
            "PL": self.nzcv["N"] == 0,
            # 溢出条件
            "VS": self.nzcv["V"] == 1,
            # 无溢出条件
            "VC": self.nzcv["V"] == 0,
            # 大于条件
            "HI": self.nzcv["C"] == 1 and self.nzcv["Z"] == 0,
            # 小于等于条件
            "LS": self.nzcv["C"] == 0 or self.nzcv["Z"] == 1,
            # 大于等于条件
            "GE": self.nzcv["N"] == self.nzcv["V"],
            # 小于条件
            "LT": self.nzcv["N"] != self.nzcv["V"],
            # 大于条件
            "GT": self.nzcv["Z"] == 0 and self.nzcv["N"] == self.nzcv["V"],
            # 小于等于条件
            "LE": self.nzcv["Z"] == 1 or self.nzcv["N"] != self.nzcv["V"],
        }
        # 根据条件字符串获取对应的条件判断逻辑，如果条件字符串不存在，则返回False
        return conditions.get(condition.upper(), False)

    def format_nzcv(self):
        """
        将NZCV（Negative, Zero, Carry, Overflow）状态寄存器的值格式化为16进制字符串。

        Args:
            无

        Returns:
            str: 格式化后的NZCV状态寄存器值的16进制字符串表示，形如"NZCV: 0xXXXXXXXX"。

        """
        value = 0
        value |= self.nzcv["N"] << 31
        value |= self.nzcv["Z"] << 30
        value |= self.nzcv["C"] << 29
        value |= self.nzcv["V"] << 28
        return f"NZCV: 0x{value:08X}"

    def __repr__(self):
        """
        返回一个表示该对象的字符串，包括所有寄存器的状态。

        Args:
            无参数。

        Returns:
            str: 返回一个表示该对象的字符串，包括所有寄存器的状态。

        """
        reg_states = [
            f"X{i}: 0x{self.registers[i] & 0xFFFFFFFFFFFFFFFF:016X} | W{i}: 0x{self.registers[i] & 0xFFFFFFFF:016X}"
            for i in range(31)
        ]
        reg_states.append(
            f"SP: 0x{self.sp & 0xFFFFFFFFFFFFFFFF:016X} | FP: 0x{self.fp & 0xFFFFFFFFFFFFFFFF:016X}"
        )
        reg_states.append(
            f"LR: 0x{self.lr & 0xFFFFFFFFFFFFFFFF:016X} | PC: 0x{self.pc & 0xFFFFFFFFFFFFFFFF:016X}"
        )
        reg_states.append(self.format_nzcv())
        reg_states.append(f"NZCV: {''.join(f'{k}{v} ' for k, v in self.nzcv.items())}")
        return "\n".join(reg_states)


class ARM64Simulator:
    _memory = {}
    _programs = None
    after_hook = None
    before_hook = None

    def __init__(
        self, _memory, step_pause=False, verbose=False, output_file=None, max_step=1000
    ):
        """
        初始化函数，用于设置模拟器实例的初始状态

        Args:
        - _memory: 内存实例，用于存储和读取指令和数据
        - step_pause: 是否在单步执行时暂停，默认为False
        - verbose: 是否打印调试信息，默认为False
        - output_file: 输出文件名，默认为None
        - max_step: 最大执行指令数，默认为当前函数总指令长度

        Returns:
        - None

        """
        self.regs = ARM64Registers()
        self._memory = _memory
        self.instruction_length = 0x04
        self.jump = False
        self.ret = False
        self.base_address = 0x100000000
        self.current_pc = 0x0
        self.step_pause = step_pause
        self.verbose = verbose
        self.size = 0x0
        self.output_file = output_file
        self.empty_output_file()
        self.max_step = max_step
        self.step_count = 0

    def set_output_file(self, output_file):
        """
        设置输出文件并清空文件内容。

        Args:
            output_file (str): 输出文件的路径。

        Returns:
            None

        """
        self.output_file = output_file
        self.empty_output_file()

    def empty_output_file(self):
        """
        清空输出文件内容
        """
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write("")

    def append_output_file(self, data):
        """
        将数据追加到输出文件中
        如果文件已存在则追加，否则创建新文件

        Args:
        - data: 要追加到输出文件中的数据

        Returns:
        - None

        """
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(data)

    def hook_instruction(self, before=None, after=None):
        """
        为 ARM64 指令添加前置和后置钩子函数。

        Args:
            before (callable, optional): 前置钩子函数，传入三个参数：vm, opcode, operands。
            after (callable, optional): 后置钩子函数，传入三个参数：vm, opcode, operands。

        Returns:
            None

        """
        if before:
            if len(before.__code__.co_varnames) != 3:
                print("before_hook 函数参数数量不正确，应该为 (vm, opcode, operands)")
            else:
                self.before_hook = before
        if after:
            if len(after.__code__.co_varnames) != 3:
                print("after_hook 函数参数数量不正确，应该为 (vm, opcode, operands)")
            else:
                self.after_hook = after

    def step(self, instruction):
        """
        对给定的指令进行解析并执行。

        Args:
            instruction (str): 待解析的指令字符串。

        Returns:
            None

        """
        if self.step_count < self.max_step:
            if self.ret:
                return
            instruction = self.parse(instruction)
            self.step_count += 1
        return instruction

    def run(self, asm_code, pc, max_step=None):
        """
        Args:
        asm_code: dict, 包含汇编指令及其对应机器码和地址的字典
        pc: int, 程序计数器初始值

        Returns:
        None

        Description:
        模拟汇编代码的执行过程，直到遇到返回指令或者PC超出指令范围为止。

        在每个指令执行后，会将执行结果更新到寄存器中，并且输出对应的机器码和执行结果。

        如果当前PC不在指令范围内，则输出错误信息，并等待用户按下回车键后继续执行。

        在执行过程中，如果遇到跳转指令，则将PC更新为跳转地址，并标记jump为True。

        在执行过程中，如果设置了verbose参数为True，则会在每次执行后输出当前寄存器的状态。

        在执行过程中，如果设置了step_pause参数为True，则会在每次执行后等待用户按下回车键后继续执行。
        """
        self.set_register("PC", pc)
        self.base_address = pc
        self.size = max(asm_code.keys()) - self.base_address
        self._programs = asm_code

        self.step_count = 0
        if not max_step:
            self.max_step = self.size
        while not self.ret and self.step_count < self.max_step:
            self.current_pc = int(self.get_register("PC"))
            if self.current_pc in self._programs:
                instruction = self._programs[self.current_pc]["instruction"]
                ophex = self._programs[self.current_pc]["ophex"]
                if not self.output_file:
                    print(f"RUN# 0x{self.current_pc:016X}:\t{ophex}\t{instruction}")
                instruction = self.step(instruction)
                self.append_output_file(
                    f"0x{self.current_pc:016X}:\t{ophex}\t{instruction}\n"
                )
                # 更新 self._programs
                if self.current_pc in self._programs:
                    self._programs[self.current_pc]["instruction"] = instruction
                    # todo instructon 需要翻译为 ophex
            else:
                print(f"ERR# 0x{self.current_pc:016X}")
                if (
                    self.current_pc < self.base_address
                    or self.current_pc >= self.base_address + self.size
                ):
                    print(f"JUMPOUT: 0x{self.current_pc:016X}")
                    break
                # 遇到未知指令，等待用户按下回车键后继续执行，如果按'q'键则退出，按'r'键则打印寄存器状态
                while True:
                    input_c = input(
                        "按回车继续，按 'q' 退出，按 'r' 打印寄存器状态，按 'm' 打印内存状态: "
                    )
                    if input_c == "q":
                        self.ret = True
                        break
                    elif input_c == "r":
                        self.print_register()
                        continue
                    elif input_c == "m":
                        self.print_memory()
                        continue
                    else:
                        break
            if not self.jump:
                self.next()
            self.jump = False
            if self.verbose:
                print(self.regs)
            if self.step_pause:
                input("按回车继续...")

    def next(self):
        """
        将PC寄存器中的值更新为下一条指令的地址。

        Args:
            无

        Returns:
            无

        """
        self.current_pc = self.get_register("PC")
        self.current_pc += self.instruction_length
        self.set_register("PC", self.current_pc)

    def print_register(self):
        """
        打印寄存器列表。

        Args:
            无

        Returns:
            无

        """
        print("Registers".center(50, "-") + "\n")
        print(self.regs)

    def print_memory(self):
        """
        打印内存中的信息。

        Args:
            无

        Returns:
            无

        """
        mem_state = "Memory".center(50, "-") + "\n"
        for address, value in self._memory.items():
            # 如果 address 是数值，则格式化为16进制，如果是字符串，则是一个对象，需要获取它的地址和方法名
            if isinstance(address, int):
                mem_state += f"0x{address:016X}: 0x{value:016X}\n"
            else:
                mem_state += (
                    f"#{address}: 0x{value['address']:016X} {value['methname']}\n"
                )
        print(mem_state)

    def parse(self, instruction):
        """
        解析指令并执行对应的操作。

        Args:
            instruction (str): 待解析的指令字符串。

        Returns:
            None

        """
        parts = instruction.split()
        opcode = parts[0]
        operands = parts[1:]

        # 支持修改操作数，并返回新指令
        if self.before_hook:
            opcode, operands = self.before_hook(self, opcode, operands)
        opcode, operands = getattr(
            self, f"op_{opcode.lower()}", self.unknown_instruction
        )(opcode, operands)
        if self.after_hook:
            opcode, operands = self.after_hook(self, opcode, operands)

        operands = self.clean_operands(operands)
        instruction = f"{opcode}  {", ".join(operands)}"
        return instruction

    def unknown_instruction(self, opcode, operands):
        """
        处理未知指令的函数。

        Args:
            self: 类的实例对象。
            operands: 指令的操作数列表。

        Returns:
            无返回值。

        """
        print("遇到未知指令。", operands)
        return opcode, operands

    def safe_eval(self, expr):
        """
        安全计算字符串表达式并返回结果。

        Args:
            expr (str): 待计算的字符串表达式。

        Returns:
            int: 表达式计算结果，如果表达式包含不安全字符或计算错误则返回0。

        """
        try:
            expr = expr.replace("#", "").replace("var_s", "0x").replace("var_", "-0x")
            allowed_chars = set("0123456789abcdefABCDEFxX+-*/# ")
            if all(char in allowed_chars for char in expr):
                return eval(expr)
            else:
                print("表达式中包含不安全字符。", expr)
                return 0
        except Exception as e:
            print(f"表达式 '{expr}' 计算错误: {e}")
            return 0

    def parse_stp_operands(self, operands):
        """
        将STP指令的操作数解析为寄存器、基址、偏移量和写回标志。

        Args:
            operands (list): 包含STP指令操作数的列表。

        Returns:
            tuple: 包含寄存器、基址、偏移量和写回标志的元组。

        """
        parts = "".join(operands).split(",")
        reg1 = parts[0].strip()
        reg2 = parts[1].strip()
        memory_expr = "".join(parts[2:])
        end_index = memory_expr.find("]")
        base_part = memory_expr[:end_index]
        base = base_part[base_part.find("[") + 1 :].strip()
        offset_expr = (
            base_part[base_part.find("#") + 1 :].strip() if "#" in base_part else "0"
        )
        write_back = memory_expr[end_index + 1 :].strip() == "!"
        if "#" in base:
            base = base.split("#")[0]
        offset = self.safe_eval(offset_expr)
        return reg1, reg2, base, offset, write_back

    def op_stp(self, opcode, operands):
        """
        将两个寄存器的值存储到由基址寄存器和偏移量确定的内存地址中。

        Args:
            operands (list): 包含操作数的列表，格式为 [reg1, reg2, base, offset, write_back]。
                其中，reg1 和 reg2 是要存储的寄存器，base 是基址寄存器，offset 是偏移量，write_back 表示是否需要写回。

        Returns:
            None

        """
        reg1, reg2, base, offset, write_back = self.parse_stp_operands(operands)
        base_address = self.get_register(base)
        actual_address = base_address + offset
        value1 = self.get_register(reg1)
        value2 = self.get_register(reg2)
        self.set_memory(actual_address, value1)
        self.set_memory(actual_address + 8, value2)
        if write_back:
            self.set_register(base, actual_address)
        return opcode, operands

    def op_ret(self, opcode, operands):
        """
        设置当前对象的ret属性为True，并返回None。

        Args:
            operands (list): 运算操作数列表。

        Returns:
            None: 无返回值。

        """
        self.ret = True
        return opcode, operands

    def op_br(self, opcode, operands):
        """
        将目标地址作为程序计数器PC的值，并设置跳转标志为True。

        Args:
            operands (list): 包含目标地址的列表，长度为1。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest = operands[0]
        val = self.get_value(dest)
        self.set_register("PC", val)
        self.jump = True
        try:
            operands[0] = f"#0x{val:016X}"
        except:
            print(dest)
        return opcode, operands

    def op_ldr(self, opcode, operands):
        """
        从内存中加载数据到寄存器中

        Args:
            operands (list): 操作数列表，包含目标寄存器名、内存地址表达式等

        Returns:
            None

        """
        dest = operands[0].replace(",", "")
        mem_expr = operands[1].strip("[]")
        parts = mem_expr.split(",")
        self.clean_operands(parts)
        base = parts[0]
        offset = parts[1]
        extend_type = None
        pager = None
        shift = 0
        if len(parts) > 2:
            extension_part = parts[2]
            if "#" in extension_part:
                extend_type, shift = extension_part.split("#")
                shift = int(shift)
        elif len(parts) == 2:
            offset = parts[1].split("@")[0]
            pager = parts[1].split("@")[1]
            extend_type = None
            shift = 0
        self._ldr(dest, base, offset, pager, extend_type, shift)
        return opcode, operands

    def _ldr(self, dest, base, offset, pager, extend_type=None, shift=0):
        """
        根据给定的参数计算偏移量，并将计算结果存储在目标寄存器中

        Args:
            dest (str): 目标寄存器的名称
            base (str): 基准寄存器的名称
            offset (str): 偏移量的值，可以是以'#'开头的内存地址，也可以是寄存器的名称
            pager (str): 分页方式，可以是'PAGE'或'PAGEOFF'
            extend_type (str, optional): 扩展类型，可以是'UXTW', 'SXTW', 'UXTH', 'SXTH', 'UXTB', 'SXTB'之一，默认为None
            shift (int, optional): 左移位数，默认为0

        Returns:
            None

        """
        base_value = self.get_register(base)
        if "#" in offset:
            if "off_" in offset:
                offset_value = self.get_memory(int("0x" + offset[5:], 0))
            else:
                offset_value = self.get_memory(self.get_memory(offset)["methname"])[
                    "address"
                ]
        else:
            offset_value = self.get_register(offset)
        if pager == "PAGE":
            offset_value = offset_value & ~0xFFF
        if extend_type == "UXTW":
            offset_value = ctypes.c_uint32(offset_value).value
            offset_value <<= shift
        elif extend_type == "SXTW":
            offset_value = ctypes.c_int32(offset_value).value
            offset_value <<= shift
        elif extend_type == "UXTH":
            offset_value = ctypes.c_uint16(offset_value).value
            offset_value <<= shift
        elif extend_type == "SXTH":
            offset_value = ctypes.c_int16(offset_value).value
            offset_value <<= shift
        elif extend_type == "UXTB":
            offset_value = ctypes.c_uint8(offset_value).value
            offset_value <<= shift
        elif extend_type == "SXTB":
            offset_value = ctypes.c_int8(offset_value).value
            offset_value <<= shift
        else:
            offset_value <<= shift

        if pager == "PAGEOFF":
            value = offset_value
        else:
            address = base_value + offset_value
            value = self.get_memory(address)
        self.set_register(dest, value)

    def op_adrp(self, opcode, operands):
        """
        根据给定的操作数，计算地址并设置到寄存器中。

        Args:
            operands (list): 操作数列表，包括目标寄存器和标签及分页类型。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest_reg = operands[0]
        label = operands[1].split("@")[0]
        pager = operands[1].split("@")[1]
        page_address = 0x0
        page_address = self.get_value(label)
        if pager == "PAGE":
            # 页对齐：页地址 = 页地址 & ~0xFFF，页地址的低12位清零，高20位保留
            page_address = page_address & ~0xFFF
        elif pager == "PAGEOFF":
            # 页偏移：页地址 = 页地址 - (页地址 & ~0xFFF)
            page_address = page_address - (page_address & ~0xFFF)
        self.set_register(dest_reg, page_address)
        return opcode, operands

    def op_adrl(self, opcode, operands):
        """
        设置寄存器值为操作数对应的地址值。

        Args:
            operands: 包含两个元素的列表，第一个元素为寄存器名，第二个元素为地址值或地址标签名。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest = operands[0]
        if "off_" in operands[1]:
            address = int("0x" + operands[1][4:], 0)
        else:
            address = self.get_value(operands[1])
        self.set_register(dest, address)

        # 跳过
        p = "#" + hex(address)
        if p.startswith("#") and len(p) >= 10:
            if not self.get_register("PC") + self.instruction_length in self._programs:
                self.next()
        return opcode, operands

    def op_cset(self, opcode, operands):
        """
        设置条件标志寄存器。

        Args:
            operands (list): 包含操作数的列表，格式为 [目标寄存器, 条件表达式]。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest = operands[0]
        condition = operands[1].upper()
        condition_met = self.regs.check_condition(condition)
        self.set_register(dest, 1 if condition_met else 0)
        return opcode, operands

    def op_cmp(self, opcode, operands):
        """
        执行比较指令。

        Args:
            operands (list): 包含两个操作数的列表。

        Returns:
            None

        """
        self.clean_operands(operands)
        op1 = operands[0]
        op2 = operands[1]
        result = self.get_value(op1) - self.get_value(op2)

        # 设置负标志位N,设置零标志位Z,设置进位标志位C,设置溢出标志位V

        self.regs.set_register("N", 1 if result < 0 else 0)
        self.regs.set_register("Z", 1 if result == 0 else 0)
        self.regs.set_register(
            "C", 1 if self.get_value(op1) >= self.get_value(op2) else 0
        )
        self.regs.set_register(
            "V",
            (
                1
                if (
                    (self.get_value(op1) ^ self.get_value(op2)) < 0
                    and (result ^ self.get_value(op1)) < 0
                )
                else 0
            ),
        )
        return opcode, operands

    def op_mov(self, opcode, operands):
        """
        将源操作数src的值移动到目标操作数dest的寄存器中。

        Args:
            operands: 包含目标操作数和源操作数的列表。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest = operands[0]
        src = self.get_value(operands[1])
        self.set_register(dest, src)
        """
               原始指令
        59 1F 8A 52    mov    w25,#0x50fa
        D9 53 A4 72    movk   w25,#0x229e, LSL #16
               IDA 指令优化后的汇编代码
        59 1F 8A 52    MOV    W25, #0x229E50FA
        D9 53 A4 72
        
        原始指令：
        第一行指令 59 1F 8A 52 对应的是 mov w25, #0x50fa，这条指令将立即数 0x50fa 移动到寄存器 w25 中。
        第二行指令 D9 53 A4 72 对应的是 movk w25, #0x229e, LSL #16，这条指令使用 movk，即“move keep”，
        将 0x229e 移动到 w25 的高16位，同时保留其他位不变。LSL #16 表示将 0x229e 左移16位，然后将这个值写入 w25。
        IDA优化后的汇编代码：
        MOV W25, #0x229E50FA 这条指令直接将完整的32位立即数 0x229E50FA 移动到寄存器 w25 中。
        IDA在分析过程中识别到了两条原始指令实际上是联合构成一个完整的32位立即数，
        因此它优化这两条指令为一条更简洁明了的指令。
        """
        # 探测立即数是否为32位，如果是则合并，即PC地址主动移位1次
        # 在这个虚机中的 memory 也不会存在该地址
        p = operands[1]
        if p.startswith("#") and len(p) >= 10:
            if not self.get_register("PC") + self.instruction_length in self._programs:
                self.next()
        return opcode, operands

    def op_add(self, opcode, operands):
        """
        加法操作。

        Args:
            operands (list): 包含三个操作数的列表。
                - dest (int): 目标寄存器。
                - src1 (int): 源寄存器1。
                - src2 (int): 源操作数2。

        Returns:
            None

        """
        self.clean_operands(operands)
        dest = operands[0]
        src1 = operands[1]
        src2 = self.get_value(operands[2])
        self.set_register(dest, self.get_register(src1) + src2)
        return opcode, operands

    def clean_operands(self, operands):
        """
        去除操作数中的逗号。

        Args:
            operands (list): 需要去除逗号的操作数列表。

        Returns:
            list: 去除逗号后的操作数列表。

        """
        for i in range(len(operands)):
            s = operands[i]
            if s.endswith(","):
                operands[i] = s[:-1]

        return operands

    def get_register(self, reg):
        """
        获取指定寄存器的值

        Args:
            reg (str): 寄存器名称

        Returns:
            Any: 寄存器的值，类型取决于寄存器本身的类型

        """
        return self.regs.get_register(reg)

    def set_register(self, reg, value):
        """
        将给定的寄存器设置为给定值。

        Args:
            reg (str): 要设置的寄存器的名称。
            value (int): 要将寄存器设置的值。

        Returns:
            None

        """
        self.regs.set_register(reg, value)

    def get_memory(self, address):
        """
        获取指定地址的内存值。

        Args:
            address (str): 内存地址，可以是十进制或十六进制字符串。

        Returns:
            int: 地址对应的内存值。

        """
        if isinstance(address, str):
            if "#" in address:
                address = address[1:]
        if address not in self._memory:
            self._memory[address] = 0
        return self._memory[address]

    def set_memory(self, address, value):
        """
        设置内存地址上的值。

        Args:
            address (int): 内存地址。
            value (int): 要设置的值。

        Returns:
            None

        """
        self._memory[address] = value

    def get_value(self, value):
        """
        获取值。

        Args:
            value (str): 需要获取值的字符串。

        Returns:
            int: 返回获取到的整数值。

        """
        if value[0] == "#":
            if "off_" in value:
                return int("0x" + value[5:], 0)
            elif "selRef_" in value:
                return self.get_memory(value[1:])["address"]
            else:
                return int(value[1:], 0)
        if len(value) >= 4 and value[0:4] == "off_":
            return self.get_memory(int("0x" + value[4:], 0))
        if len(value) >= 4 and value[0:4] == "loc_":
            return self.get_memory(int("0x" + value[4:], 0))

        if value[0] == "W" or value[0] == "X" or len(value) <= 3:
            return self.get_register(value)

        return value


# HOOK 代码范例


def _nop_ops_after_hook(vm, op_name, operands):
    """
    将指定的操作转换为NOP操作。
    """
    if op_name == "CSET":
        print(f" AFTER-HOOK# {op_name} to NOP")
        op_name = "NOP"
        operands = []
    return op_name, operands


def _br_x9_after_hook(vm, op_name, operands):
    """
    hook操作 BR X9 的地址
    """
    if op_name == "BR":
        print(f" AFTER-HOOK# 0x{vm.get_register('PC'):016X}\t{op_name} {operands[0]}")
    return op_name, operands


def _dynamic_op_after_hook(vm, op_name, operands):
    """
    修改分支 CSET 从 LT 改成 GE
    执行后修改，下次执行修改后的
    """
    if op_name == "CSET":
        reg_name = operands[0]
        reg_name = reg_name.replace(",", "")
        operands[1] = "GE"
        print(
            f" AFTER-HOOK# 0x{vm.get_register('PC'):016X}\t{op_name} {reg_name}:0x{vm.get_register(reg_name):016X} , {operands[1]}"
        )
    return op_name, operands


def _cset_lt_to_ge_before_hook(vm, op_name, operands):
    """
    修改分支 CSET 从 LT 改成 GE
    执行前修改
    """
    if op_name == "CSET":
        reg_name = operands[0].replace(",", "")
        operands[1] = "GE"
        print(
            f"BEFORE-HOOK# 0x{vm.get_register('PC'):016X}\t{op_name} {reg_name}:0x{vm.get_register(reg_name):016X} , {operands[1]}"
        )
    return op_name, operands


if __name__ == "__main__":
    # 准备输入的内容
    asm_data = read_file("samples/diasm.s")
    asm_code = load_asm_code(asm_data)
    write_to_file("samples/asm_code.json", asm_code)
    memory_lines = read_file("samples/memory.s")
    memory_data = parse_memory_lines(memory_lines)
    write_to_file("samples/memory_data.json", memory_data)

    # 执行vm
    # 第一个分支
    vm = ARM64Simulator(
        memory_data, step_pause=False, verbose=False, output_file="samples/output1.s"
    )
    vm.hook_instruction(after=_br_x9_after_hook)
    vm.run(asm_code, pc=0x100AE0D64)

    # 第二个分支
    vm.set_output_file("samples/output2.s")
    vm.hook_instruction(before=_cset_lt_to_ge_before_hook)
    vm.run(asm_code=asm_code, pc=0x100AE0D64)

    # 跑完第一个分支，动态修改地址，跑第二个分支
    vm.set_output_file("samples/output3.s")
    vm.hook_instruction(after=_dynamic_op_after_hook)
    vm.run(asm_code=asm_code, pc=0x100AE0D64)
