# 无界 · 云巅之上

一个基于 **PoW（工作量证明）+ 短效令牌 + AES-256-GCM 双层加密** 的 PHP 前端安全架构。

## 架构

```
浏览器                          PHP 服务器
 │                                │
 ├─ challenge ──────────────────→ │  生成随机挑战 + 难度
 │                                │
 ├─ PoW(SHA-256) ───────────────→ │  验证 hash 前缀 N 位为零
 │                                │
 ├─ fetch token ←──────────────── │  签发 32B AES 令牌（5 分钟有效）
 │                                │
 ├─ request page ───────────────→ │  用 令牌 加密 page 返回
 │                                │
 ├─ AES-GCM 解密并渲染 ←───────── │
```

### 核心文件

| 文件 | 作用 |
|------|------|
| `index.html` | 前端 bootloader：PoW 计算 + AES-GCM 解密 |
| `loader.php` | 服务端入口：challenge→PoW→token→page |
| `inc/crypto.php` | AES-256-GCM 加解密函数 |
| `inc/page.enc` | MASTER_KEY 加密后的页面内容 |
| `inc/config.php` | **你的配置**（从 `config.sample.php` 复制） |
| `.htaccess` | 禁止访问隐藏文件/密钥文件 |

### 安全机制

1. **PoW 防刷**：客户端需计算 SHA-256，hash 前 5 位十六进制为 0（~16bit 工作量），约 16-50ms
2. **短效令牌**：5 分钟过期，IP 绑定，防重放
3. **双层加密**：`MASTER_KEY` 加密静态页面 → `令牌密钥` 加密传输
4. **CSRF 保护**：每次请求刷新 CSRF token

## 太阳系 · 实时开普勒轨道

`solar-system/` 是一个纯前端 Three.js 3D 太阳系模拟，基于 NASA JPL 历元数据：

- 开普勒椭圆轨道 + 牛顿-拉夫逊解算行星位置
- Canvas 2D 程序化纹理（大陆、木纹、火星坑等）
- 速度控制（1× 到 周/秒）
- 点击行星拉近视角 + 信息展示
- Bloom 泛光、大气层、土星环、月球轨

## 部署

```bash
# 1. 复制配置
cp main-site/inc/config.sample.php main-site/inc/config.php

# 2. 编辑 config.php，填入你自己的密钥
#    php -r "echo bin2hex(random_bytes(32));"

# 3. 部署到 Nginx/Apache
#    - 确保 PHP 启用 OpenSSL 扩展
#    - 确保 /tmp 目录可写入
```

## 安全须知

- **任何情况下不要提交 `config.php` 到版本控制**（已包含 `.gitignore`）
- `MASTER_KEY` 是页面加密的核心密钥，丢失后 page.enc 无法还原
- 建议定期轮换 MASTER_KEY 并重新加密 page.enc
