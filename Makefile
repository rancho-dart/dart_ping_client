# 定义目标文件
TARGET = dt_ping

# 编译规则
all: $(TARGET)

$(TARGET): dt_ping.go
	go build -o $(TARGET) $<

# 清理规则
clean:
	rm -f $(TARGET)