# messagetag

命令行工具：查询版本，或为单个消息文件生成 HMAC-SHA-256 认证标签。

## 依赖

- CMake ≥ 3.20，支持 C++20 的编译器
- OpenSSL ≥ 3.0（仅需 libcrypto，用于 HMAC-SHA-256 的标准实现）

若 OpenSSL 安装在非标准位置，可通过 `OPENSSL_ROOT_DIR` 环境变量或
CMake 变量指定其前缀，例如：

```sh
OPENSSL_ROOT_DIR=/path/to/openssl cmake -S . -B build
```

## 构建与运行

```sh
cmake -S . -B build
cmake --build build
./build/messagetag --version
```

输出：

```text
messagetag 0.1.0
```

## 生成认证标签

```sh
messagetag tag --key-hex <十六进制密钥> --file <消息文件路径>
```

- `--key-hex` 表示原始密钥字节的十六进制编码：每两位十六进制字符对应一个
  字节，大小写均可，开头的零会保留（例如 `0001` 是两个字节 `0x00 0x01`，
  而不是数值 1）。密钥必须非空、位数为偶数，只含 `0-9` 和 `a-f`，
  不接受 `0x` 前缀或空白字符。
- `--file` 指向消息文件。文件内容按原始字节完整读取：不作文本解释，
  不去掉末尾换行，不转换换行形式，不忽略零字节。空文件也是合法消息。
  文件路径本身不参与认证，相同密钥与相同内容在不同路径下结果相同。

成功时标准输出只有一行 64 个小写十六进制字符的标签（以换行结束），
退出码为 0：

```sh
$ printf 'hello world\n' > message.txt
$ messagetag tag --key-hex 0001 --file message.txt
ded200654bdd857c729038d559f1e3abb7484fadaf08bc88060ef39ef55eb24c
```

即：密钥字节 `0x00 0x01` 对消息字节 `hello world\n`（含末尾换行）计算的
HMAC-SHA-256 为上面这行标签。

错误行为：

- 文件无法打开或读取失败：标准错误输出说明，退出码 1，标准输出不写任何内容。
- 缺少必需参数、密钥格式错误或出现不认识的参数：标准错误输出原因及用法，
  退出码 2（错误信息不会回显密钥内容）。
