#!/bin/bash

# 简单Java性能分析工具
# 使用方法: ./run_profiler.sh <duration>

set -e

DURATION=${1:-10}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================="
echo "  简单Java性能分析工具"
echo "========================================="
echo ""

# 检查是否编译成功
if [ ! -f TestProgram.class ]; then
    echo "正在编译组件..."
    make
fi

echo ""
echo "1. 启动Java测试程序..."
java -agentpath:./libsimple_agent_file.so TestProgram > /dev/null 2>&1 &
JAVA_PID=$!
echo "Java进程 PID: $JAVA_PID"

# 等待Java进程启动和符号生成
sleep 2

# 检查perf map文件
if [ ! -f /tmp/perf-simple.map ]; then
    echo "警告: 未找到符号文件，仍将继续..."
fi

echo ""
echo "2. 开始性能采样 (${DURATION}秒)..."
if which perf > /dev/null 2>&1; then
    perf record -F 99 -g -p $JAVA_PID -o perf.data -- sleep $DURATION &
    PERF_PID=$!
else
    echo "未找到perf命令，将使用符号生成模式"
    sleep $DURATION
    echo "符号已保存至 /tmp/perf-simple.map"
fi

wait $PERF_PID 2>/dev/null || true

echo ""
echo "3. 停止Java进程..."
kill $JAVA_PID 2>/dev/null || true
wait $JAVA_PID 2>/dev/null || true

# 如果有perf.data文件，生成报告
if [ -f perf.data ]; then
    echo ""
    echo "4. 解析性能数据..."
    if [ -f /tmp/perf-simple.map ]; then
        cp /tmp/perf-simple.map ./ 2>/dev/null || true
    fi
    
    echo "正在使用perf生成报告..."
    perf script -i perf.data > perf.script.txt 2>/dev/null || true
    
    if [ -f perf.script.txt ]; then
        if [ -f symbol_parser ] && [ -f perf-simple.map ]; then
            ./symbol_parser perf-simple.map perf.script.txt
        else
            echo "perf.script.txt已生成，可以手动分析"
        fi
    fi
    
    echo ""
    echo "分析完成！"
    echo "  perf.data         原始数据"
    echo "  perf.script.txt   解析后的脚本"
    echo "  perf-simple.map   Java符号表"
    echo "  profiler.folded   折叠格式输出"
else
    echo ""
    echo "符号收集完成！"
    echo "  perf-simple.map   Java符号表"
fi

echo ""
echo "如果有perf-simple.map，可以使用perf查看火焰图"
echo "生成火焰图的步骤:"
echo "  1. 下载FlameGraph工具"
echo "     git clone https://github.com/brendangregg/FlameGraph"
echo "  2. 使用perf和符号表生成火焰图"
echo "     perf script -i perf.data | FlameGraph/stackcollapse-perf.pl > profiler.folded"
echo "     FlameGraph/flamegraph.pl profiler.folded > profiler.svg"
echo ""

exit 0
