# Kubernetes 源快照内存

普通 Metricbeat 周期采集和原有 GetStateMetricsFamilies/GetStateMetricsFamiliesFor 继续保留 family DTO 缓存与重复读取语义。sampler 在显式 BeginStreamingCollection/EndCollection 生命周期内使用可选直接折叠路径，普通 BeginCollection 不开启它。

当配置的全部 state metricset 均有已注册、受支持映射，且 Prometheus client 实现可选 VisitFamiliesFor 时：

- 单次读取 HTTP，按 64 KiB 文本批次解析，以借用的单条样本回调分发给关心该 family 的映射。回调不得保留样本或 LabelPair 指针；原有 family API 返回的独立数据不受此约束。
- 边解析边按实体 key 合并到共享字段表与紧凑值数组，不保留完整 family/Metric/LabelPair 树，也不为每个样本构造 allLabels/keyLabels/labels 等临时嵌套 map。有限字符串驻留只保留独立副本，不让一个小标签引用整条原始 series 文本。
- HTTP 完整解析成功后才发布快照；限额、解压、读取或解析失败丢弃局部结果并缓存本次 Run 的错误，不提交半份数据。响应限额仍约束完整解压后输入，包括未映射 family。
- 访问快照时按最多 128 条构造事件；sum/count 聚合仅保留分组状态，并按原顺序将前序派生事件加入后续聚合。info 字段保持最终覆盖优先级，只有 info、没有普通指标的实体不输出。
- 同一 Run、同一 endpoint 的多个消费者共享快照，未显式释放时重复读取仍可行。sampler 每个 wrapper 完成后调用 ReleaseCollectionMetricSet，按配置中 mapping 消费者次数递减，仅在最后一个消费者结束时释放对应 join 行；其他 mapping/endpoint 不受影响，已失败 wrapper 不提交半份结果。endpoint 全部 wrapper 完成后再释放其 Summary 和剩余紧凑源快照；未支持的映射/client 保留原完整 family 路径。提前释放可降低 join 与 sampler 列共存的内存，不消除初始解析所需的完整 join 峰值。

Pod metadata watcher 使用 transforming informer，在进入缓存前保存紧凑对象与紧凑 container/status 数组，访问 Store 或调用 metadata handler 时短暂恢复所需的 Pod 视图。保留 UID、ResourceVersion、owner、所有 labels/annotations、节点、IP、ready/reason、容器名字/ID、资源要求等被 metadata/资源指标消费的字段；不保存未使用的 env、ports、volumes、managedFields 等大对象。只影响此模块私有 metadata watcher，不替换全局 Kubernetes client，也不改变业务 Pod API 的原始数据。List/Watch 过滤、更新版本、删除/tombstone、resync 和取消继续生效。

metadata 的不可变字符串/mapstr.M 子树在 MetricsRepo 内共享，不再只共享 labels/annotations。指纹只用于查找，完整比较确认等价；形状、nil/empty 和不支持类型保留原语义。独立池最多 4096 项、2 MiB 估算预算与 10 分钟空闲 TTL，淘汰只移除池索引，不损坏仍被对象引用的树；普通 enrichment 仍克隆可变输出。预算不是所有 metadata 对象或进程 RSS 的硬限制。

这不是全链路 O(1)：紧凑 join 仍随实体/字段数增长，必要全局聚合随分组数增长；API List 仍完整解码后再转换，kubelet 每个活跃 endpoint 仍完整解析 Summary，sampler 开始消费前仍构建压缩后的指标列。普通/未知映射兼容路径、Debug 的完整结果、序列化、RPC/WAL 与队列预算也有独立成本。

完整同输入对照、失败证据和结果见工作空间 `tmp/k8s-e2e-pressure/SOURCE_OPTIMIZATION.md`。生产 OOM 安全与 P95 不由本地模拟保证。
