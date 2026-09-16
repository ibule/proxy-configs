# proxy-configs

Shadowrocket 配置与规则集，入口为 `shadowrocket/main.conf`。

## 富途、老虎规则自动更新

GitHub Actions 工作流 **Sync broker rules** 每天北京时间 **10:23** 拉取上游，有变更时自动提交至默认分支。也可以在仓库 **Actions → Sync broker rules → Run workflow** 手动触发，选择默认分支。修改同步脚本、来源配置或本地补充规则并推送至 `main` 后也会触发。

| 输出文件 | 上游 | 本地补充 |
| --- | --- | --- |
| `shadowrocket/Futu.list` | [v2fly/domain-list-community · futu](https://github.com/v2fly/domain-list-community/blob/master/data/futu) | `rules/local/Futu.list` |
| `shadowrocket/tiger.list` | [blackmatrix7/ios_rule_script · TigerFintech](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/TigerFintech/TigerFintech.list) | `rules/local/tiger.list` |

这两个输出文件由脚本生成。需要永久保留的自定义域名请加入对应的 `rules/local/*.list`；需要排除的域名请加入 `rules/brokers.json` 的 `exclude_suffixes`，同时排除其子域名。初次迁移保留了项目原有规则。

同步会排序、去重，并保留上游的精确域名或后缀匹配语义。只有域名规则会被接受；上游新增 IP、正则或 include 等尚未支持的语法时会报错，需检查后调整脚本。当前排除共享统计/CDN 域名及已核实的非官方 `futuapi.com`。

下载失败、空内容、格式错误、核心域名缺失、上游条目过少/超过 500 条，或一次删除超过现有规则的 25%，都会中止同步。所有来源验证成功后才写入输出文件。正常的上游删除会同步生效，但本地补充项会继续保留。没有内容变化时不会产生提交。

`Futu_Extended.list` 中的共享服务及 IP 网段继续手动维护；本工作流仅自动同步上表的域名集。`main.conf` 已引用两个输出文件并指向「港股APP」，引用地址保持不变。

### 启用

将这些文件提交并推送到 GitHub 默认分支，确保仓库启用 Actions、允许工作流使用 `contents: write`。使用仓库自带的 `GITHUB_TOKEN`，无需额外配置 Secret。如果分支保护禁止机器人直接推送，工作流会失败，需要按仓库规则调整写入方式；不会强制推送。

GitHub 定时任务可能延迟；公共仓库长时间无活动时定时工作流可能被停用，可在 Actions 页面重新启用。详见 [GitHub schedule 文档](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。

远端更新后，Shadowrocket 仍需刷新规则集才能使用新内容。

### 本地运行

仅使用 Python 3 标准库，无需安装依赖：

```sh
python3 -B -m unittest discover -s tests -v
python3 -B scripts/sync_broker_rules.py --check
python3 -B scripts/sync_broker_rules.py
```

`--check` 不写文件：无差异返回 0，有差异返回 1，下载或校验失败返回 2。

上游规则的许可分别保存在 `licenses/`：v2fly 为 MIT，blackmatrix7 为 GPL-2.0。生成文件保留来源、许可及修改说明；合并、筛选记录可通过 Git 历史查看。
