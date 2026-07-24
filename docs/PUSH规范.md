# Push 规范

## 禁止上传

```
CLAUDE.md           # Claude 个人配置
logs/*              # 运行时日志 (samples.csv, batch_results.json)
reports/*           # 生成的报告
samples/batches/*   # 生成的样本批次
samples/results/*   # 执行结果
app/uploads/*       # 上传的文件 (webshell等)
__pycache__/        # Python 缓存
*.pyc
.DS_Store
Thumbs.db
```

以上已在 `.gitignore` 配置，`git add -A` 时自动排除。

## 提交规范

**禁止 Claude 协作者**：提交信息不要带 `Co-Authored-By: Claude` 行。

当前 git 已配置 `Kittyyyy` 为用户，提交时只显示你的名字。

## Push 前检查清单

```bash
# 1. 确认没有不该传的文件
git status

# 2. 确认 gitignore 生效
git status --ignored | grep -E "logs/|reports/|batches/|results/|__pycache__"

# 3. 确认提交信息不含 Claude
git log -1

# 4. Push
git push origin main
```

## 如果已经误传

```bash
# 从 git 跟踪中移除（保留本地文件）
git rm --cached <file>
# 更新 .gitignore 添加该文件
# 提交并 push
```
