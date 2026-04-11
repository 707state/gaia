# GAIA WebUI

`gaia-webui` 是 GAIA 的前端控制台，基于 `React + TypeScript + Vite` 构建，用于展示监控状态、事件流、告警、策略配置和 AI 分析界面。

## 开发依赖

- `Node.js` 18+
- `pnpm` 9+

安装 `pnpm`：

```bash
npm install -g pnpm
```

安装前端依赖：

```bash
pnpm install
```

## 开发模式

在 `gaia-webui` 目录下启动前端开发服务器：

```bash
pnpm dev
```

默认使用 Vite 本地开发服务。

## 生产构建

单独构建前端：

```bash
pnpm build
```

构建产物输出到：

```text
gaia-webui/dist/
```

## 与 Rust 后端的集成

前端构建产物会被 `gaia-xdp` 通过 `rust-embed` 嵌入到后端二进制中。

现在在项目根目录执行：

```bash
cargo build
```

会自动触发本目录下的：

```bash
pnpm build
```

因此，根目录构建前请确认：

- 系统中已经安装 `pnpm`
- 本目录依赖已经执行过 `pnpm install`

## 目录说明

- `src/`：前端源码
- `src/app/types.ts`：共享类型定义
- `src/app/constants.ts`：前端常量与模拟数据
- `src/app/utils.ts`：通用工具函数
- `src/app/components/`：可复用组件与配置面板
- `dist/`：生产构建产物
