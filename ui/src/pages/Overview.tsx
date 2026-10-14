import { useMemo } from "react";
import { Button, Col, List, Row, Space, Tag, Typography } from "antd";
import { useResource } from "../useResource";
import {
  alertTypeLabel,
  deviceName,
  DeviceTable,
  Empty,
  Fresh,
  Metric,
  OverviewGuide,
  PageHeading,
  Panel,
  time,
  UpdatedAt,
} from "../components";
import type { Alert, DeviceSummary } from "../types";

export function Overview({
  openDevice,
  openAlerts,
}: {
  openDevice: (id: string) => void;
  openAlerts: () => void;
}) {
  const devices = useResource<DeviceSummary[]>("/api/devices"),
    alerts = useResource<Alert[]>("/api/alerts");
  const stats = useMemo(() => {
    const all = devices.data ?? [];
    const online = all.filter((d) => d.onlineState === "Online");
    return {
      pass: online.filter((d) => d.currentVerdict === "PASS").length,
      fail: online.filter((d) => d.currentVerdict === "FAIL").length,
      unknown: online.filter((d) => d.currentVerdict === "UNKNOWN").length,
      offline: all.length - online.length,
    };
  }, [devices.data]);
  const attention = (devices.data ?? []).filter(
    (d) => d.currentVerdict !== "PASS" || d.onlineState !== "Online",
  );
  const openAlertList = (alerts.data ?? []).filter((a) => a.state !== "Resolved");
  return (
    <>
      <PageHeading
        title="合规总览"
        description="所有结论以管理端当前数据为准。失联终端单独统计，其上次结论仅作历史参考。"
        extra={<UpdatedAt at={devices.updatedAt} refreshing={devices.refreshing} />}
      />
      <Fresh error={devices.error} loading={devices.loading}>
        <Space orientation="vertical" size={16} style={{ width: "100%" }}>
          <OverviewGuide devices={devices.data ?? []} />
          <Row gutter={[16, 16]}>
            <Col xs={12} lg={6}>
              <Metric label="通过" value={stats.pass} tone="good" caption="在线终端" />
            </Col>
            <Col xs={12} lg={6}>
              <Metric label="不通过" value={stats.fail} tone="danger" caption="存在确认违规" />
            </Col>
            <Col xs={12} lg={6}>
              <Metric
                label="无法判断"
                value={stats.unknown}
                tone="warning"
                caption="检查不完整或防护未验证"
              />
            </Col>
            <Col xs={12} lg={6}>
              <Metric
                label="失联 / 疑似失联"
                value={stats.offline}
                tone="neutral"
                caption="不计入当前通过"
              />
            </Col>
          </Row>
          <Row gutter={[16, 16]}>
            <Col xs={24} xl={15}>
              <Panel title={`需要关注的终端（${attention.length}）`}>
                <DeviceTable
                  devices={attention.slice(0, 8)}
                  onSelect={openDevice}
                  pageSize={false}
                  compact
                />
              </Panel>
            </Col>
            <Col xs={24} xl={9}>
              <Panel
                title={`未恢复告警（${openAlertList.length}）`}
                actions={
                  <Button type="link" onClick={openAlerts}>
                    查看全部
                  </Button>
                }
              >
                <Fresh error={alerts.error} loading={alerts.loading}>
                  {openAlertList.length === 0 ? (
                    <Empty title="当前没有未恢复的告警" />
                  ) : (
                    <List
                      size="small"
                      dataSource={openAlertList.slice(0, 6)}
                      renderItem={(a) => (
                        <List.Item>
                          <Space orientation="vertical" size={2}>
                            <Space size={4}>
                              <Tag color={a.type === "Violation" ? "error" : "warning"}>
                                {alertTypeLabel(a.type)}
                              </Tag>
                              <Typography.Text strong>{a.summary}</Typography.Text>
                            </Space>
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              {deviceName({
                                hostName: a.hostName,
                                note: devices.data?.find((d) => d.id === a.deviceId)?.note,
                              })}{" "}
                              · {time(a.lastSeen)}
                              {a.acknowledged ? " · 已确认" : ""}
                            </Typography.Text>
                          </Space>
                        </List.Item>
                      )}
                    />
                  )}
                </Fresh>
              </Panel>
            </Col>
          </Row>
        </Space>
      </Fresh>
    </>
  );
}
