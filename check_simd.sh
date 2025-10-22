#!/bin/bash
DISASM=disasm.txt

echo "🔍 检查 FP16 浮点指令..."
grep -E "\.[48]h" "$DISASM" | grep -E "f(add|sub|mul|mla|div|sqrt|neg)" && echo "⚠️ 发现 FP16 指令！" || echo "✅ 无 FP16 浮点"

echo -e "\n🔍 检查 DotProd 指令..."
grep -E "(sdot|udot)" "$DISASM" && echo "⚠️ 发现 DotProd 指令！" || echo "✅ 无 DotProd"

echo -e "\n🔍 检查基础 NEON (float32)..."
grep "\.4s" "$DISASM" | head -3