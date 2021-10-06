// 695.744 - Reverse Engineering and Vulnerability Analysis - Fall 2021
// Programming Assignment 1

using System;
using System.Collections.Generic;
using System.IO;

namespace PS1
{
    /// <summary>
    /// Class to store machine code and provide tracking for 
    /// counting bytes, current bytes being processed by an
    /// instruction and any labels
    /// </summary>
    public class MachineCode
    {
        /// <summary>
        /// Count of machine code bytes 
        /// </summary>
        public int Count { get { return _bytes.Count; } }

        /// <summary>
        /// How many bytes have been processed since last reset
        /// </summary>
        public int ProcessedByteCount { get; private set; }

        /// <summary>
        /// String of bytes that have been accessed since last reset
        /// </summary>
        public string ByteString { get; private set; }


        /// <summary>
        /// Current byte value being processed
        /// </summary>
        public byte CurrentByte { get { return _currentByte.Value; } }


        /// <summary>
        /// Linked list of machine code bytes
        /// </summary>
        private LinkedList<byte> _bytes;

        /// <summary>
        /// First byte accessed after latest reset
        /// </summary>
        private LinkedListNode<byte> _startingByte;

        /// <summary>
        /// Current byte node being processed
        /// </summary>
        private LinkedListNode<byte> _currentByte;

        /// <summary>
        /// Dictionary of labels: byte line => mnemonic
        /// </summary>
        private Dictionary<int, string> _labels = new Dictionary<int, string>();

        public MachineCode(byte[] bytes)
        {
            _bytes = new LinkedList<byte>(bytes);
        }

        /// <summary>
        /// Initialize machine code for analysis and return the first byte
        /// </summary>
        public void Initialize()
        {
            _labels.Clear();
            ProcessedByteCount = 1;
            _currentByte = _bytes.First;
            _startingByte = _currentByte;

            if (_currentByte != null)
            {
                ByteString = _currentByte.Value.ToString("X2");
            }
        }

        /// <summary>
        /// Is the current byte null?
        /// </summary>
        /// <returns></returns>
        public bool IsCurrentByteNull()
        {
            return _currentByte == null;
        }

        /// <summary>
        /// Is the next byte null?
        /// </summary>
        /// <returns></returns>
        public bool IsNextByteNull()
        {
            if (_currentByte == null)
            {
                return true;
            }

            return _currentByte.Next == null;
        }

        /// <summary>
        /// Advance to next machine code byte
        /// </summary>
        public void AdvanceToNext(bool currentByteSet = false)
        {
            // Work around for rollback and first byte is invalid
            if(!currentByteSet)
            {
                _currentByte = _currentByte.Next;
            }
            ++ProcessedByteCount;

            if (_startingByte == null)
            {
                _startingByte = _currentByte;
            }

            if (_currentByte != null)
            {
                ByteString += _currentByte.Value.ToString("X2");
            }
        }

        /// <summary>
        /// Peek the next byte without advancing to it
        /// </summary>
        /// <returns></returns>
        public byte PeekNextByte()
        {
            if (IsNextByteNull())
            {
                return 0x0;
            }

            return _currentByte.Next.Value;
        }

        /// <summary>
        /// Reset variables used for processing
        /// </summary>
        public void Reset()
        {
            ProcessedByteCount = 0;
            ByteString = string.Empty;
            _startingByte = null;
        }

        /// <summary>
        /// Rollback to the starting byte
        /// </summary>
        public void Rollback()
        {
            _currentByte = _startingByte;
            Reset();
            AdvanceToNext(true);
        }

        /// <summary>
        /// Add label found in machine code
        /// </summary>
        /// <param name="byteLocation"></param>
        /// <param name="label"></param>
        public void AddLabel(int byteLocation, string label)
        {
            if (_labels.ContainsKey(byteLocation))
            {
                // Label added by another statement
                return;
            }

            _labels.Add(byteLocation, label);
        }

        /// <summary>
        /// Does the current line number have a label?  If so return it in out label
        /// </summary>
        /// <param name="lineCount"></param>
        /// <param name="label"></param>
        /// <returns></returns>
        public bool LineHasLabel(int lineCount, out string label)
        {
            label = string.Empty;
            if (_labels.ContainsKey(lineCount))
            {
                label = _labels[lineCount];
                return true;
            }

            return false;
        }

    }

    /// <summary>
    /// Class to represent an x86 instruction
    /// </summary>
    public class Instruction
    {
        /// <summary>
        /// Class to represent an x86 operand
        /// </summary>
        public class Operand
        {
            public enum OperandTypes : byte
            {
                EAX = 0b000000,
                ECX = 0b000001,
                EDX = 0b000010,
                EBX = 0b000011,
                ESP = 0b000100,
                EBP = 0b000101,
                ESI = 0b000110,
                EDI = 0b000111,
                R = 0b001000,
                M = 0b001001,
                RM = 0b001010,
                IMM8 = 0b001011,
                IMM16 = 0b001100,
                IMM32 = 0b001101,
                REL8 = 0b001110,
                REL32 = 0b001111,
                CONST = 0b010000,
                None = 0b100000
            }

            public readonly OperandTypes OperandType;
            public readonly byte Constant;

            public Operand()
            {
                OperandType = OperandTypes.None;
                Constant = 0;
            }

            public Operand(OperandTypes operandType)
            {
                OperandType = operandType;
                Constant = 0;
            }

            public Operand(OperandTypes operandType, byte constant)
            {
                OperandType = operandType;
                Constant = constant;
            }

            /// <summary>
            /// Get mnemonic for the operand
            /// </summary>
            /// <param name="modrm"></param>
            /// <param name="currentInstructionCount"></param>
            /// <param name="operandMnemonic"></param>
            /// <param name="machineCode"></param>
            /// <returns></returns>
            public bool GetOperandMnemonic((byte mod, byte reg, byte rm) modrm, int currentInstructionCount, ref string operandMnemonic, MachineCode machineCode)
            {
                if (OperandType == OperandTypes.None)
                {
                    // Nothing to do
                    return true;
                }
                else if (OperandType == OperandTypes.CONST)
                {
                    // Const type just returns string representation of constant
                    operandMnemonic = Constant.ToString();
                    return true;
                }
                else if ((byte)OperandType <= 0b111)
                {
                    // Operand encoded with register
                    var registerMnemonic = string.Empty;
                    if (!GetRegisterMnemonic((byte)OperandType, ref registerMnemonic))
                    {
                        // Could not get register mnemonic
                        return false;
                    }

                    operandMnemonic = registerMnemonic;
                    return true;
                }
                else if (OperandType == OperandTypes.R)
                {
                    // Operand type is a regiester in modrm reg
                    var registerMnemonic = string.Empty;
                    if (!GetRegisterMnemonic(modrm.reg, ref registerMnemonic))
                    {
                        // Could not get register mnemonic
                        return false;
                    }

                    operandMnemonic = registerMnemonic;
                    return true;
                }
                else if (OperandType == OperandTypes.RM || OperandType == OperandTypes.M)
                {
                    // Operand is an rm or m that needs to be decoded
                    switch (modrm.mod)
                    {
                        case 0b00:
                            {
                                if (modrm.rm == 0b101)
                                {
                                    // SPECIAL CASE: If the MOD is 00 and the R/M value is 101, this is a
                                    // special case. This indicates the r/m32 location is a memory location
                                    // that is a displacement32 only.
                                    int disp = 0;
                                    if (!GetDisplacement(4, ref disp, machineCode))
                                    {
                                        return false;
                                    }

                                    operandMnemonic = $"[0x{disp.ToString("X2").ToLowerInvariant().PadLeft(4 * 2, '0')}]";
                                }
                                else
                                {
                                    // The r/m32 operand's memory address is located in the r/m register.
                                    var registerMnemonic = string.Empty;
                                    if (!GetRegisterMnemonic(modrm.rm, ref registerMnemonic))
                                    {
                                        // Could not get register mnemonic
                                        return false;
                                    }

                                    operandMnemonic = $"[{registerMnemonic}]";
                                }
                            }
                            return true;
                        case 0b01:
                            {
                                //The r/m32 operand’s memory address is located in the r/m register + a 1-byte displacement.
                                var registerMnemonic = string.Empty;
                                if (!GetRegisterMnemonic(modrm.rm, ref registerMnemonic))
                                {
                                    // Could not get register mnemonic
                                    return false;
                                }

                                int disp = 0;
                                if (!GetDisplacement(1, ref disp, machineCode))
                                {
                                    // Could not get immediate value
                                    return false;
                                }

                                if(disp >= 0)
                                {
                                    operandMnemonic = $"[{registerMnemonic} + {disp}]";
                                }
                                else
                                {
                                    operandMnemonic = $"[{registerMnemonic} - {Math.Abs(disp)}]";
                                }

                                
                            }
                            return true;
                        case 0b10:
                            {
                                // The r/m32 operand’s memory address is located in the r/m register + a 4-byte displacement.
                                var registerMnemonic = string.Empty;
                                if (!GetRegisterMnemonic(modrm.rm, ref registerMnemonic))
                                {
                                    // Could not get register mnemonic
                                    return false;
                                }

                                int disp = 0;
                                if (!GetDisplacement(4, ref disp, machineCode))
                                {
                                    // Could not get immediate value
                                    return false;
                                }

                                operandMnemonic = $"[{registerMnemonic} + 0x{disp.ToString("X2").ToLowerInvariant().PadLeft(4 * 2, '0')}]";
                            }
                            return true;
                        case 0b11:
                            {
                                // The r/m32 operand is a direct register access.
                                var registerMnemonic = string.Empty;
                                if (!GetRegisterMnemonic(modrm.rm, ref registerMnemonic))
                                {
                                    // Could not get register mnemonic
                                    return false;
                                }

                                operandMnemonic = registerMnemonic;
                            }
                            return true;
                        default:
                            return false;
                    }
                }
                else if (OperandType == OperandTypes.IMM8 || OperandType == OperandTypes.IMM16 || OperandType == OperandTypes.IMM32)
                {
                    // Operand is an immediate type
                    byte numberOfBytes = 0;
                    int immediate = 0;
                    switch (OperandType)
                    {
                        case OperandTypes.IMM8:
                            numberOfBytes = 1;
                            break;
                        case OperandTypes.IMM16:
                            numberOfBytes = 2;
                            break;
                        case OperandTypes.IMM32:
                            numberOfBytes = 4;
                            break;
                    }

                    if (!GetImmediate(numberOfBytes, ref immediate, machineCode))
                    {
                        return false;
                    }

                    if(numberOfBytes == 1)
                    {
                        operandMnemonic = $"{immediate}";
                    }
                    else
                    {
                        operandMnemonic = $"0x{immediate.ToString("X2").ToLowerInvariant().PadLeft(numberOfBytes * 2, '0')}";
                    }
                    

                    return true;
                }
                else if (OperandType == OperandTypes.REL8 || OperandType == OperandTypes.REL32)
                {
                    // Operand is a relative displacement 
                    byte numberOfBytes = 0;
                    int relative = 0;
                    switch (OperandType)
                    {
                        case OperandTypes.REL8:
                            numberOfBytes = 1;
                            break;
                        case OperandTypes.REL32:
                            numberOfBytes = 4;
                            break;
                    }

                    if (!GetRelative(numberOfBytes, ref relative, machineCode))
                    {
                        // Could not get the relative displacement
                        return false;
                    }

                    relative += currentInstructionCount + machineCode.ProcessedByteCount;

                    // Even though REL8 is only 1 byte, still display it as 4 bytes
                    operandMnemonic = $"offset_{relative.ToString("X2").PadLeft(4 * 2, '0')}h";
                    machineCode.AddLabel(relative, operandMnemonic);

                    return true;
                }
                else
                {
                    return false;
                }
            }

            //Get passed in register as a mnemonic
            private bool GetRegisterMnemonic(byte register, ref string registerMnemonic)
            {
                if (register > 0b111)
                {
                    // register byte isn't a register
                    return false;
                }

                switch (register)
                {
                    case (byte)OperandTypes.EAX:
                        registerMnemonic = "eax";
                        return true;
                    case (byte)OperandTypes.ECX:
                        registerMnemonic = "ecx";
                        return true;
                    case (byte)OperandTypes.EDX:
                        registerMnemonic = "edx";
                        return true;
                    case (byte)OperandTypes.EBX:
                        registerMnemonic = "ebx";
                        return true;
                    case (byte)OperandTypes.ESP:
                        registerMnemonic = "esp";
                        return true;
                    case (byte)OperandTypes.EBP:
                        registerMnemonic = "ebp";
                        return true;
                    case (byte)OperandTypes.ESI:
                        registerMnemonic = "esi";
                        return true;
                    case (byte)OperandTypes.EDI:
                        registerMnemonic = "edi";
                        return true;
                    default:
                        return false;
                }
            }

            // Calculate relative displacement
            private bool GetRelative(byte numberOfBytes, ref int relative, MachineCode machineCode)
            {
                var bytes = new byte[4];
                for (var i = 0; i < numberOfBytes; ++i)
                {
                    machineCode.AdvanceToNext();
                    if (machineCode.IsCurrentByteNull())
                    {
                        return false;
                    }

                    bytes[i] = machineCode.CurrentByte;
                }

                if (numberOfBytes == 1)
                {
                    // If rel8, extend the sign
                    if ((bytes[0] & 0b10000000) == 0b10000000)
                    {
                        bytes[1] = 0xFF;
                        bytes[2] = 0xFF;
                        bytes[3] = 0xFF;
                    }
                    else
                    {
                        bytes[1] = 0x00;
                        bytes[2] = 0x00;
                        bytes[3] = 0x00;
                    }
                }
                else if (numberOfBytes != 4)
                {
                    // If for some reason 1 or 4 bytes was not passed in, this should fail
                    return false;
                }

                relative = BitConverter.ToInt32(bytes, 0);

                return true;
            }

            /// <summary>
            /// Get displacement value
            /// </summary>
            /// <param name="numberOfBytes"></param>
            /// <param name="constant"></param>
            /// <param name="machineCode"></param>
            /// <returns></returns>
            private bool GetDisplacement(byte numberOfBytes, ref int displacement, MachineCode machineCode)
            {
                var bytes = new byte[4];
                for (var i = 0; i < numberOfBytes; ++i)
                {
                    machineCode.AdvanceToNext();
                    if (machineCode.IsCurrentByteNull())
                    {
                        return false;
                    }

                    bytes[i] = machineCode.CurrentByte;
                }

                if (numberOfBytes == 1)
                {
                    // If disp8, extend the sign
                    if ((bytes[0] & 0b10000000) == 0b10000000)
                    {
                        bytes[1] = 0xFF;
                        bytes[2] = 0xFF;
                        bytes[3] = 0xFF;
                    }
                    else
                    {
                        bytes[1] = 0x00;
                        bytes[2] = 0x00;
                        bytes[3] = 0x00;
                    }
                }
                else if (numberOfBytes != 4)
                {
                    // If for some reason 1 or 4 bytes was not passed in, this should fail
                    return false;
                }

                displacement = BitConverter.ToInt32(bytes, 0);

                return true;
            }

            /// <summary>
            /// Get immediate value 
            /// </summary>
            /// <param name="numberOfBytes"></param>
            /// <param name="constant"></param>
            /// <param name="machineCode"></param>
            /// <returns></returns>
            private bool GetImmediate(byte numberOfBytes, ref int constant, MachineCode machineCode)
            {
                var bytes = new byte[numberOfBytes];
                for (var i = 0; i < numberOfBytes; ++i)
                {
                    machineCode.AdvanceToNext();
                    if (machineCode.IsCurrentByteNull())
                    {
                        return false;
                    }

                    bytes[i] = machineCode.CurrentByte;
                }

                // This will be used by true immediates
                if (numberOfBytes == 1)
                {
                    constant = bytes[0];
                }
                else if (numberOfBytes == 2)
                {
                    constant = BitConverter.ToInt16(bytes, 0);
                }
                else if (numberOfBytes == 4)
                {
                    constant = BitConverter.ToInt32(bytes, 0);
                }
                else
                {
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Class to represent an x86 opcode extension
        /// </summary>
        public class OpcodeExtension
        {
            public enum ExtensionTypes
            {
                None,
                Constant,
                Register
            }

            public readonly ExtensionTypes ExtensionType;
            public readonly byte Constant;

            public OpcodeExtension()
            {
                ExtensionType = ExtensionTypes.None;
                Constant = 0;
            }

            public OpcodeExtension(ExtensionTypes extensionType)
            {
                ExtensionType = extensionType;
                Constant = 0;
            }

            public OpcodeExtension(ExtensionTypes extensionType, byte constant)
            {
                ExtensionType = extensionType;
                Constant = constant;
            }
        }

        public enum AddressingModeTypes
        {
            NotRequired,
            Partial,        // 00/01/10
            Full            // 00/01/10/11
        }

        // Fields that represent parts of the instruction.
        // Readonly so they cannot be altered after creation
        public readonly byte Opcode;
        public readonly OpcodeExtension Extension;
        public readonly AddressingModeTypes AddressingMode;


        public readonly Operand Operand1;
        public readonly Operand Operand2;
        public readonly Operand Operand3;

        public readonly string Mnemonic;

        /// <summary>
        /// Opcode only constructor
        /// </summary>
        /// <param name="opcode"></param>
        /// <param name="mnemonic"></param>
        public Instruction(byte opcode, string mnemonic)
        {
            Opcode = opcode;
            Extension = new OpcodeExtension();
            AddressingMode = AddressingModeTypes.NotRequired;

            Operand1 = new Operand();
            Operand2 = new Operand();
            Operand3 = new Operand();

            Mnemonic = mnemonic;
        }

        /// <summary>
        /// One operand constructor
        /// </summary>
        /// <param name="opcode"></param>
        /// <param name="addressingMode"></param>
        /// <param name="operand1"></param>
        /// <param name="extension"></param>
        /// <param name="mnemonic"></param>
        public Instruction(byte opcode, AddressingModeTypes addressingMode, Operand operand1, OpcodeExtension extension, string mnemonic)
        {
            Opcode = opcode;
            Extension = extension;
            AddressingMode = addressingMode;

            Operand1 = operand1;
            Operand2 = new Operand();
            Operand3 = new Operand();

            Mnemonic = mnemonic;
        }

        /// <summary>
        /// Two operand constructor
        /// </summary>
        /// <param name="opcode"></param>
        /// <param name="addressingMode"></param>
        /// <param name="operand1"></param>
        /// <param name="operand2"></param>
        /// <param name="extension"></param>
        /// <param name="mnemonic"></param>
        public Instruction(byte opcode, AddressingModeTypes addressingMode, Operand operand1, Operand operand2, OpcodeExtension extension, string mnemonic)
        {
            Opcode = opcode;
            Extension = extension;
            AddressingMode = addressingMode;

            Operand1 = operand1;
            Operand2 = operand2;
            Operand3 = new Operand();

            Mnemonic = mnemonic;
        }

        /// <summary>
        /// Three operand constructor
        /// </summary>
        /// <param name="opcode"></param>
        /// <param name="addressingMode"></param>
        /// <param name="operand1"></param>
        /// <param name="operand2"></param>
        /// <param name="operand3"></param>
        /// <param name="extension"></param>
        /// <param name="mnemonic"></param>
        public Instruction(byte opcode, AddressingModeTypes addressingMode, Operand operand1, Operand operand2, Operand operand3, OpcodeExtension extension, string mnemonic)
        {
            Opcode = opcode;
            Extension = extension;
            AddressingMode = addressingMode;

            Operand1 = operand1;
            Operand2 = operand2;
            Operand3 = operand3;

            Mnemonic = mnemonic;
        }

        /// <summary>
        /// Get instruction mnemonic
        /// </summary>
        /// <param name="currentInstructionCount"></param>
        /// <param name="machineCode"></param>
        /// <param name="mnemonic"></param>
        /// <returns></returns>
        public bool GetMnemonic(int currentInstructionCount, MachineCode machineCode, ref string mnemonic)
        {
            (byte mod, byte reg, byte rm) modrm = (0xFF, 0x00, 0x00);

            if (AddressingMode == AddressingModeTypes.Partial || AddressingMode == AddressingModeTypes.Full)
            {
                machineCode.AdvanceToNext();

                if (machineCode.IsCurrentByteNull())
                {
                    // Addressing mode is not none, but no byte to decode for modrm
                    return false;
                }

                modrm = DecodeMODRM(machineCode.CurrentByte);

                if (modrm.mod == 0b11 && AddressingMode == Instruction.AddressingModeTypes.Partial)
                {
                    // MOD determined to be 0b11, but invalid for partial address mode
                    return false;
                }
            }

            var operand1Mnemoic = string.Empty;
            var operand2Mnemoic = string.Empty;
            var operand3Mnemoic = string.Empty;

            if (!Operand1.GetOperandMnemonic(modrm, currentInstructionCount, ref operand1Mnemoic, machineCode))
            {
                return false;
            }

            if (!Operand2.GetOperandMnemonic(modrm, currentInstructionCount, ref operand2Mnemoic, machineCode))
            {
                return false;
            }

            if (!Operand3.GetOperandMnemonic(modrm, currentInstructionCount, ref operand3Mnemoic, machineCode))
            {
                return false;
            }

            mnemonic += $"{Mnemonic}{(operand1Mnemoic.Length > 0 ? " " : "")}{operand1Mnemoic}{(operand2Mnemoic.Length > 0 ? ", " : "")}{operand2Mnemoic}{(operand3Mnemoic.Length > 0 ? ", " : "")}{operand3Mnemoic}";
            return true;
        }

        /// <summary>
        /// Decode MODRM byte
        /// </summary>
        /// <param name="modrm"></param>
        /// <returns></returns>
        public static (byte mod, byte reg, byte rm) DecodeMODRM(byte modrm)
        {
            // Adapted from code provided in class
            var mod = Convert.ToByte((modrm & 0xC0) >> 6);
            var reg = Convert.ToByte((modrm & 0x38) >> 3);
            var rm = Convert.ToByte((modrm & 0x07));

            return (mod, reg, rm);
        }
    }

    /// <summary>
    /// Class that represents the disassembler
    /// </summary>
    class Disassembler
    {
        /// <summary>
        /// Supported prefixes: opcode => mnemonic
        /// </summary>
        private static IReadOnlyDictionary<byte, string> Prefixes;

        /// <summary>
        /// Supported prefixed instructions: opcode => instruction
        /// </summary>
        private static IReadOnlyDictionary<byte, Instruction[]> PrefixedInstructions;

        /// <summary>
        /// Supported instructions: opcode => instruction
        /// </summary>
        private static IReadOnlyDictionary<byte, Instruction[]> Instructions;

        /// <summary>
        /// Static constructor that builds all supported instructions
        /// </summary>
        static Disassembler()
        {
            #region Instructions
            /*
                Mnemonic/Syntax         Opcode              Addressing Modes
                add eax, imm32          0x05 id             MODR/M Not Required
                add r/m32, imm32        0x81 /0 id          00/01/10/11
                add r/m32, r32          0x01 /r             00/01/10/11
                add r32, r/m32          0x03 /r             00/01/10/11
                and eax, imm32          0x25 id             MODR/M Not Required
                and r/m32, imm32        0x81 /4 id          00/01/10/11
                and r/m32, r32          0x21 /r             00/01/10/11
                and r32, r/m32          0x23 /r             00/01/10/11
                call rel32              0xE8 cd             Note: treat cd as id
                call r/m32              0xFF /2             00/01/10/11
                clflush m8              0x0F 0xAE /7        00/01/10 Note: m8 can be a [disp32] only, a [reg], a [reg + disp8], or a [reg + disp32]. Addressing mode 11 is illegal.
                cmp eax, imm32          0x3D id             MODR/M Not Required
                cmp r/m32, imm32        0x81 /7 id          00/01/10/11
                cmp r/m32, r32          0x39 /r             00/01/10/11
                cmp r32, r/m32          0x3B /r             00/01/10/11
                dec r/m32               0xFF /1             00/01/10/11
                dec r32                 0x48 + rd           MODR/M Not Required
                idiv r/m32              0xF7 /7             00/01/10/11
                imul r/m32              0xF7 /5             00/01/10/11
                imul r32, r/m32         0x0F 0xAF /r        00/01/10/11
                imul r32, r/m32, imm32  0x69 /r id          00/01/10/11
                inc r/m32               0xFF /0             00/01/10/11
                inc r32                 0x40 + rd           MODR/M Not Required
                jmp rel8                0xEB cb             Note: treat cb as ib
                jmp rel32               0xE9 cd             Note: treat cd as id
                jmp r/m32               0xFF /4             00/01/10/11
                jz rel8                 0x74 cb             Note: treat cb as ib
                jz rel32                0x0f 0x84 cd        Note: treat cd as id
                jnz rel8                0x75 cb             Note: treat cb as ib
                jnz rel32               0x0f 0x85 cd        Note: treat cd as id
                lea r32, m              0x8D /r             00/01/10    Note: m can be a [disp32] only, a [reg], a [reg + disp8], or a [reg + disp32]. Addressing mode 11 is illegal.
                mov r32, imm32          0xB8+rd id          MODR/M Not Required
                mov r/m32, imm32        0xC7 /0 id          00/01/10/11
                mov r/m32, r32          0x89 /r             00/01/10/11
                mov r32, r/m32          0x8B /r             00/01/10/11
                movsd                   0xA5                MODR/M Not Required
                mul r/m32               0xF7 /4             00/01/10/11
                neg r/m32               0xF7 /3             00/01/10/11
                nop                     0x90                MODR/M Not Required Note: this is really xchg eax, eax 
                not r/m32               0xF7 /2             00/01/10/11
                or eax, imm32           0x0D id             MODR/M Not Required
                or r/m32, imm32         0x81 /1 id          00/01/10/11
                or r/m32, r32           0x09 /r             00/01/10/11
                or r32, r/m32           0x0B /r             00/01/10/11
                out imm8, eax           0xE7 ib             MODR/M Not Required
                pop r/m32               0x8F /0             00/01/10/11
                pop r32                 0x58 + rd           MODR/M Not Required
                push r/m32              0xFF /6             00/01/10/11
                push r32                0x50 + rd           MODR/M Not Required
                push imm32              0x68 id             MODR/M Not Required
                repne cmpsd             0xF2 0xA7           MODR/M Not Required Note: 0xF2 is the repne prefix
                retf                    0xCB                MODR/M Not Required
                retf imm16              0xCA iw             MODR/M Not Required Note: iw is a 16-bit immediate
                retn                    0xC3                MODR/M Not Required
                retn imm16              0xC2 iw             MODR/M Not Required Note: iw is a 16-bit immediate
                sal r/m32, 1            0xD1 /4             00/01/10/11
                sar r/m32, 1            0xD1 /7             00/01/10/11
                shr r/m32, 1            0xD1 /5             00/01/10/11
                sbb eax, imm32          0x1D id             MODR/M Not Required
                sbb r/m32, imm32        0x81 /3 id          00/01/10/11
                sbb r/m32, r32          0x19 /r             00/01/10/11
                sbb r32, r/m32          0x1B /r             00/01/10/11#
                sub eax, imm32          0x2D id             MODR/M Not Required
                sub r/m32, imm32        0x81 /5 id          00/01/10/11
                sub r/m32, r32          0x29 /r             00/01/10/11
                sub r32, r/m32          0x2B /r             00/01/10/11
                test eax, imm32         0xA9 id             MODR/M Not Required
                test r/m32, imm32       0xF7 /0 id          00/01/10/11
                test r/m32, r32         0x85 /r             00/01/10/11
                xor eax, imm32          0x35 id             MODR/M Not Required
                xor r/m32, imm32        0x81 /6 id          00/01/10/11
                xor r/m32, r32          0x31 /r             00/01/10/11
                xor r32, r/m32          0x33 /r             00/01/10/11
            */

            var prefixes = new Dictionary<byte, string>
            {
                {0x0F, string.Empty},
                {0xF2, "repne"}
            };
            Prefixes = prefixes;


            var prefixedInstructions = new Dictionary<byte, Instruction[]>
            {
                {0x84, new Instruction[1]},
                {0x85, new Instruction[1]},
                {0xA7, new Instruction[1]},
                {0xAE, new Instruction[8]},
                {0xAF, new Instruction[1]}
            };

            // clflush
            prefixedInstructions[0xAE][7] = new Instruction(0xAE, Instruction.AddressingModeTypes.Partial, new Instruction.Operand(Instruction.Operand.OperandTypes.IMM8), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 7), "clflush");

            // imul
            prefixedInstructions[0xAF][0] = new Instruction(0xAF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "imul");

            // jz
            prefixedInstructions[0x84][0] = new Instruction(0x84, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.None), "jz");

            // jnz
            prefixedInstructions[0x85][0] = new Instruction(0x85, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.None), "jnz");

            // cmpsd
            prefixedInstructions[0xA7][0] = new Instruction(0xA7, "cmpsd");

            PrefixedInstructions = prefixedInstructions;


            var instructions = new Dictionary<byte, Instruction[]>
            {
                {0x01, new Instruction[1]},
                {0x03, new Instruction[1]},
                {0x05, new Instruction[1]},
                {0x09, new Instruction[1]},
                {0x0B, new Instruction[1]},
                {0x0D, new Instruction[1]},
                {0x19, new Instruction[1]},
                {0x1B, new Instruction[1]},
                {0x1D, new Instruction[1]},
                {0x21, new Instruction[1]},
                {0x23, new Instruction[1]},
                {0x25, new Instruction[1]},
                {0x29, new Instruction[1]},
                {0x2B, new Instruction[1]},
                {0x2D, new Instruction[1]},
                {0x31, new Instruction[1]},
                {0x33, new Instruction[1]},
                {0x35, new Instruction[1]},
                {0x39, new Instruction[1]},
                {0x3B, new Instruction[1]},
                {0x3D, new Instruction[1]},
                {0x40, new Instruction[1]},
                {0x41, new Instruction[1]},
                {0x42, new Instruction[1]},
                {0x43, new Instruction[1]},
                {0x44, new Instruction[1]},
                {0x45, new Instruction[1]},
                {0x46, new Instruction[1]},
                {0x47, new Instruction[1]},
                {0x48, new Instruction[1]},
                {0x49, new Instruction[1]},
                {0x4A, new Instruction[1]},
                {0x4B, new Instruction[1]},
                {0x4C, new Instruction[1]},
                {0x4D, new Instruction[1]},
                {0x4E, new Instruction[1]},
                {0x4F, new Instruction[1]},
                {0x50, new Instruction[1]},
                {0x51, new Instruction[1]},
                {0x52, new Instruction[1]},
                {0x53, new Instruction[1]},
                {0x54, new Instruction[1]},
                {0x55, new Instruction[1]},
                {0x56, new Instruction[1]},
                {0x57, new Instruction[1]},
                {0x58, new Instruction[1]},
                {0x59, new Instruction[1]},
                {0x5A, new Instruction[1]},
                {0x5B, new Instruction[1]},
                {0x5C, new Instruction[1]},
                {0x5D, new Instruction[1]},
                {0x5E, new Instruction[1]},
                {0x5F, new Instruction[1]},
                {0x68, new Instruction[1]},
                {0x69, new Instruction[1]},
                {0x74, new Instruction[1]},
                {0x75, new Instruction[1]},
                {0x81, new Instruction[8]},
                {0x85, new Instruction[1]},
                {0x89, new Instruction[1]},
                {0x8B, new Instruction[1]},
                {0x8D, new Instruction[1]},
                {0x8F, new Instruction[8]},
                {0x90, new Instruction[1]},
                {0xA5, new Instruction[1]},
                {0xA9, new Instruction[1]},
                {0xB8, new Instruction[1]},
                {0xB9, new Instruction[1]},
                {0xBA, new Instruction[1]},
                {0xBB, new Instruction[1]},
                {0xBC, new Instruction[1]},
                {0xBD, new Instruction[1]},
                {0xBE, new Instruction[1]},
                {0xBF, new Instruction[1]},
                {0xC2, new Instruction[1]},
                {0xC3, new Instruction[1]},
                {0xC7, new Instruction[8]},
                {0xCA, new Instruction[1]},
                {0xCB, new Instruction[1]},
                {0xD1, new Instruction[8]},
                {0xE7, new Instruction[1]},
                {0xE8, new Instruction[1]},
                {0xE9, new Instruction[1]},
                {0xEB, new Instruction[1]},
                {0xF7, new Instruction[8]},
                {0xFF, new Instruction[8]}
            };

            // add
            instructions[0x05][0] = new Instruction(0x05, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.None), "add");
            instructions[0x81][0] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 0), "add");
            instructions[0x01][0] = new Instruction(0x01, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "add");
            instructions[0x03][0] = new Instruction(0x03, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "add");

            // and
            instructions[0x25][0] = new Instruction(0x25, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "and");
            instructions[0x81][4] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 4), "and");
            instructions[0x21][0] = new Instruction(0x21, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "and");
            instructions[0x23][0] = new Instruction(0x23, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "and");

            // call
            instructions[0xE8][0] = new Instruction(0xE8, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL32), new Instruction.OpcodeExtension(), "call");
            instructions[0xFF][2] = new Instruction(0xFF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 2), "call");

            // cmp
            instructions[0x3D][0] = new Instruction(0x3D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "cmp");
            instructions[0x81][7] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 7), "cmp");
            instructions[0x39][0] = new Instruction(0x39, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "cmp");
            instructions[0x3B][0] = new Instruction(0x3B, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "cmp");

            // dec
            instructions[0xFF][1] = new Instruction(0xFF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 1), "dec");
            instructions[0x48][0] = new Instruction(0x48, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.OpcodeExtension(), "dec");
            instructions[0x49][0] = new Instruction(0x49, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ECX), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4A][0] = new Instruction(0x4A, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDX), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4B][0] = new Instruction(0x4B, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBX), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4C][0] = new Instruction(0x4C, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESP), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4D][0] = new Instruction(0x4D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBP), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4E][0] = new Instruction(0x4E, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESI), new Instruction.OpcodeExtension(), "dec");
            instructions[0x4F][0] = new Instruction(0x4F, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDI), new Instruction.OpcodeExtension(), "dec");

            // idiv
            instructions[0xF7][7] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 7), "idiv");

            // imul
            instructions[0xF7][5] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 5), "imul");
            instructions[0x69][0] = new Instruction(0x69, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "imul");

            // inc
            instructions[0xFF][0] = new Instruction(0xFF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 0), "inc");
            instructions[0x40][0] = new Instruction(0x40, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.OpcodeExtension(), "inc");
            instructions[0x41][0] = new Instruction(0x41, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ECX), new Instruction.OpcodeExtension(), "inc");
            instructions[0x42][0] = new Instruction(0x42, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDX), new Instruction.OpcodeExtension(), "inc");
            instructions[0x43][0] = new Instruction(0x43, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBX), new Instruction.OpcodeExtension(), "inc");
            instructions[0x44][0] = new Instruction(0x44, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESP), new Instruction.OpcodeExtension(), "inc");
            instructions[0x45][0] = new Instruction(0x45, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBP), new Instruction.OpcodeExtension(), "inc");
            instructions[0x46][0] = new Instruction(0x46, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESI), new Instruction.OpcodeExtension(), "inc");
            instructions[0x47][0] = new Instruction(0x47, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDI), new Instruction.OpcodeExtension(), "inc");

            // jmp
            instructions[0xEB][0] = new Instruction(0xEB, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL8), new Instruction.OpcodeExtension(), "jmp");
            instructions[0xE9][0] = new Instruction(0xE9, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL32), new Instruction.OpcodeExtension(), "jmp");
            instructions[0xFF][4] = new Instruction(0xFF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 4), "jmp");

            // jz
            instructions[0x74][0] = new Instruction(0x74, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL8), new Instruction.OpcodeExtension(), "jz");

            // jnz
            instructions[0x75][0] = new Instruction(0x75, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.REL8), new Instruction.OpcodeExtension(), "jnz");

            // lea
            instructions[0x8D][0] = new Instruction(0x8D, Instruction.AddressingModeTypes.Partial, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.M), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "lea");

            // mov
            instructions[0xB8][0] = new Instruction(0xB8, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xB9][0] = new Instruction(0xB9, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ECX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBA][0] = new Instruction(0xBA, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBB][0] = new Instruction(0xBB, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBC][0] = new Instruction(0xBC, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESP), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBD][0] = new Instruction(0xBD, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBP), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBE][0] = new Instruction(0xBE, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESI), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xBF][0] = new Instruction(0xBF, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDI), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "mov");
            instructions[0xC7][0] = new Instruction(0xC7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 0), "mov");
            instructions[0x89][0] = new Instruction(0x89, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "mov");
            instructions[0x8B][0] = new Instruction(0x8B, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "mov");

            // movsd
            instructions[0xA5][0] = new Instruction(0xA5, "movsd");

            // mul
            instructions[0xF7][4] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 4), "mul");

            // neg
            instructions[0xF7][3] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 3), "neg");

            // nop
            instructions[0x90][0] = new Instruction(0x90, "nop");

            // not
            instructions[0xF7][2] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 2), "not");

            // or
            instructions[0x0D][0] = new Instruction(0x0D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "or");
            instructions[0x81][1] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 1), "or");
            instructions[0x09][0] = new Instruction(0x09, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "or");
            instructions[0x0B][0] = new Instruction(0x0B, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "or");

            // out
            instructions[0xE7][0] = new Instruction(0xE7, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.IMM8), new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.OpcodeExtension(), "out");

            // pop
            instructions[0x8F][0] = new Instruction(0x8F, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 0), "pop");
            instructions[0x58][0] = new Instruction(0x58, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.OpcodeExtension(), "pop");
            instructions[0x59][0] = new Instruction(0x59, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ECX), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5A][0] = new Instruction(0x5A, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDX), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5B][0] = new Instruction(0x5B, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBX), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5C][0] = new Instruction(0x5C, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESP), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5D][0] = new Instruction(0x5D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBP), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5E][0] = new Instruction(0x5E, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESI), new Instruction.OpcodeExtension(), "pop");
            instructions[0x5F][0] = new Instruction(0x5F, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDI), new Instruction.OpcodeExtension(), "pop");

            // push
            instructions[0xFF][6] = new Instruction(0xFF, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 6), "push");
            instructions[0x50][0] = new Instruction(0x50, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.OpcodeExtension(), "push");
            instructions[0x51][0] = new Instruction(0x51, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ECX), new Instruction.OpcodeExtension(), "push");
            instructions[0x52][0] = new Instruction(0x52, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDX), new Instruction.OpcodeExtension(), "push");
            instructions[0x53][0] = new Instruction(0x53, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBX), new Instruction.OpcodeExtension(), "push");
            instructions[0x54][0] = new Instruction(0x54, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESP), new Instruction.OpcodeExtension(), "push");
            instructions[0x55][0] = new Instruction(0x55, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EBP), new Instruction.OpcodeExtension(), "push");
            instructions[0x56][0] = new Instruction(0x56, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.ESI), new Instruction.OpcodeExtension(), "push");
            instructions[0x57][0] = new Instruction(0x57, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EDI), new Instruction.OpcodeExtension(), "push");
            instructions[0x68][0] = new Instruction(0x68, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "push");

            // retf
            instructions[0xCB][0] = new Instruction(0xCB, "retf");
            instructions[0xCA][0] = new Instruction(0xCA, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.IMM16), new Instruction.OpcodeExtension(), "retf");

            // retn
            instructions[0xC3][0] = new Instruction(0xC3, "retn");
            instructions[0xC2][0] = new Instruction(0xC2, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.IMM16), new Instruction.OpcodeExtension(), "retn");

            // sal
            instructions[0xD1][4] = new Instruction(0xD1, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.CONST, 1), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 4), "sal");

            // sar
            instructions[0xD1][7] = new Instruction(0xD1, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.CONST, 1), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 7), "sar");

            // shr
            instructions[0xD1][5] = new Instruction(0xD1, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.CONST, 1), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 5), "shr");

            // sbb
            instructions[0x1D][0] = new Instruction(0x1D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "sbb");
            instructions[0x81][3] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 3), "sbb");
            instructions[0x19][0] = new Instruction(0x19, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "sbb");
            instructions[0x1B][0] = new Instruction(0x1B, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "sbb");

            // sub
            instructions[0x2D][0] = new Instruction(0x2D, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "sub");
            instructions[0x81][5] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 5), "sub");
            instructions[0x29][0] = new Instruction(0x29, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "sub");
            instructions[0x2B][0] = new Instruction(0x2B, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "sub");

            // test
            instructions[0xA9][0] = new Instruction(0xA9, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "test");
            instructions[0xF7][0] = new Instruction(0xF7, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 0), "test");
            instructions[0x85][0] = new Instruction(0x85, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "test");

            // xor
            instructions[0x35][0] = new Instruction(0x35, Instruction.AddressingModeTypes.NotRequired, new Instruction.Operand(Instruction.Operand.OperandTypes.EAX), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(), "xor");
            instructions[0x81][6] = new Instruction(0x81, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.IMM32), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Constant, 6), "xor");
            instructions[0x31][0] = new Instruction(0x31, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "xor");
            instructions[0x33][0] = new Instruction(0x33, Instruction.AddressingModeTypes.Full, new Instruction.Operand(Instruction.Operand.OperandTypes.R), new Instruction.Operand(Instruction.Operand.OperandTypes.RM), new Instruction.OpcodeExtension(Instruction.OpcodeExtension.ExtensionTypes.Register), "xor");

            Instructions = instructions;
            #endregion
        }

        /// <summary>
        /// Disassemble the passed in machine code
        /// </summary>
        /// <param name="machineCode"></param>
        public void Disassemble(MachineCode machineCode)
        {
            if (machineCode.Count == 0)
            {
                // No machine code passed in, nothing to do
                return;
            }

            var bytesAndMnemonics = new List<(int count, string bytes, string mnemonic)>();

            // Initialize and loop over all machine code until all instructions processed
            machineCode.Initialize();
            int currentInstructionCount = 0;
            while (!machineCode.IsCurrentByteNull())
            {
                ProcessBytes(currentInstructionCount, machineCode, out string mnemonic);
                bytesAndMnemonics.Add((currentInstructionCount, machineCode.ByteString, mnemonic));
                currentInstructionCount += machineCode.ProcessedByteCount;

                machineCode.Reset();
                machineCode.AdvanceToNext();
            }

            // After processing, print out mnemonics and labels to the screen
            foreach (var line in bytesAndMnemonics)
            {
                if (machineCode.LineHasLabel(line.count, out string label))
                {
                    System.Console.WriteLine($"{label}:");
                }

                System.Console.WriteLine(@$"{line.count.ToString("X2").PadLeft(8, '0')}:  {line.bytes.PadRight(25, ' ')}{line.mnemonic}");
            }

        }

        /// <summary>
        /// Processes bytes and attempts to get a single line mnemonic 
        /// </summary>
        /// <param name="currentInstructionCount"></param>
        /// <param name="machineCode"></param>
        /// <param name="mnemonic"></param>
        private void ProcessBytes(int currentInstructionCount, MachineCode machineCode, out string mnemonic)
        {
            mnemonic = string.Empty;

            var success = false;
            var instructionDictionary = Instructions;
            if (Prefixes.ContainsKey(machineCode.CurrentByte))
            {
                // We hit a prefix, switch to the prefixed instructions
                mnemonic = Prefixes[machineCode.CurrentByte].Length > 0 ? $"{Prefixes[machineCode.CurrentByte]} " : string.Empty;
                instructionDictionary = PrefixedInstructions;

                machineCode.AdvanceToNext();
            }

            if (!machineCode.IsCurrentByteNull() && instructionDictionary.ContainsKey(machineCode.CurrentByte))
            {
                // Supported opcode found, start processing
                Instruction instruction = null;

                var currentInstructions = instructionDictionary[machineCode.CurrentByte];
                if (currentInstructions.Length > 1)
                {
                    // Deal with extension.  Since the dictionary entry contains multiple entries, figure out which index to use
                    // based on value stored in modrm
                    if (!machineCode.IsNextByteNull())
                    {
                        // We have a byte to process, take a peek and decode it
                        var modrm = Instruction.DecodeMODRM(machineCode.PeekNextByte());

                        if (currentInstructions[modrm.reg] != null)
                        {
                            // Found instruction in used extension slot
                            instruction = currentInstructions[modrm.reg];
                        }
                    }
                }
                else
                {
                    // Found instruction
                    instruction = currentInstructions[0];
                }

                if (instruction != null)
                {
                    // We found an instruction, attempt to get the mnemonic 
                    success = instruction.GetMnemonic(currentInstructionCount, machineCode, ref mnemonic);
                }
            }

            if (!success)
            {
                // If we are unsuccessful, rollback to starting byte and print as db instruction
                machineCode.Rollback();
                mnemonic = $"db {machineCode.ByteString}";
            }
        }
    }

    /// <summary>
    /// Main program
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length != 2 || args[0] != "-i")
                {
                    System.Console.WriteLine("Usage:");
                    System.Console.WriteLine("PS1.exe -i [file path]");
                    return;
                }

                var path = args[1];
                if (!File.Exists(path))
                {
                    System.Console.WriteLine($"File does not exist as path: {path}");
                    return;
                }

                var bytes = File.ReadAllBytes(path);

                var d = new Disassembler();
                d.Disassemble(new MachineCode(bytes));
            }
            catch (Exception e)
            {
                System.Console.WriteLine("Something went horribly wrong that I did not catch. If you get this message I am sure its points off!");
                System.Console.WriteLine($"Exception message: {e.Message}");
            }
        }
    }
}
