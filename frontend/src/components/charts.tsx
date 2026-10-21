import * as echarts from "echarts";
import { useEffect, useMemo, useRef } from "react";
import { useTheme } from "../context/ThemeContext";
import { cn } from "../lib/utils";

export interface ChartSeries {
  name: string;
  data: number[];
  color: string;
  area?: boolean;
}

export function useChartTheme() {
  const { theme } = useTheme();
  return useMemo(() => {
    const dark = theme === "dark";
    return {
      dark,
      text: dark ? "#8f97ad" : "#59627a",
      strongText: dark ? "#e8ebf5" : "#111522",
      line: dark ? "rgba(255,255,255,.08)" : "rgba(20,28,48,.10)",
      panel: dark ? "#11141d" : "#ffffff",
      tooltipBg: dark ? "rgba(17,20,29,.96)" : "rgba(255,255,255,.98)",
      tooltipBorder: dark ? "rgba(255,255,255,.12)" : "rgba(20,28,48,.12)",
      accent: "#8b5cf6",
      cyan: "#22d3ee"
    };
  }, [theme]);
}

export function EChart({
  option,
  height = 260,
  className,
  onClick
}: {
  option: echarts.EChartsCoreOption;
  height?: number | string;
  className?: string;
  onClick?: (params: echarts.ECElementEvent) => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: "canvas" });
    chartRef.current = chart;
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(ref.current);
    return () => {
      observer.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, true);
  }, [option]);

  useEffect(() => {
    const chart = chartRef.current;
    if (!chart || !onClick) return;
    chart.off("click");
    chart.on("click", onClick);
    return () => {
      chart.off("click");
    };
  }, [onClick]);

  return <div ref={ref} className={cn("w-full", className)} style={{ height }} role="img" />;
}

export function TrendChart({
  labels,
  series,
  height = 250,
  showLegend = true
}: {
  labels: string[];
  series: ChartSeries[];
  height?: number;
  showLegend?: boolean;
}) {
  const theme = useChartTheme();
  const option = useMemo<echarts.EChartsCoreOption>(
    () => ({
      backgroundColor: "transparent",
      animationDuration: 700,
      grid: { left: 14, right: 18, top: showLegend ? 38 : 16, bottom: 10, containLabel: true },
      legend: showLegend
        ? {
            top: 0,
            right: 0,
            icon: "roundRect",
            itemWidth: 8,
            itemHeight: 4,
            itemGap: 16,
            textStyle: { color: theme.text, fontSize: 10 }
          }
        : undefined,
      tooltip: {
        trigger: "axis",
        backgroundColor: theme.tooltipBg,
        borderColor: theme.tooltipBorder,
        textStyle: { color: theme.strongText, fontSize: 11 },
        axisPointer: { type: "line", lineStyle: { color: theme.line } }
      },
      xAxis: {
        type: "category",
        data: labels,
        boundaryGap: false,
        axisLine: { lineStyle: { color: theme.line } },
        axisTick: { show: false },
        axisLabel: { color: theme.text, fontSize: 9, hideOverlap: true }
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: theme.line, type: "dashed" } },
        axisLabel: { color: theme.text, fontSize: 9 }
      },
      series: series.map((entry) => ({
        name: entry.name,
        type: "line",
        data: entry.data,
        smooth: 0.32,
        symbol: "circle",
        symbolSize: 4,
        showSymbol: false,
        lineStyle: { width: 2, color: entry.color },
        itemStyle: { color: entry.color },
        areaStyle: entry.area === false
          ? undefined
          : {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: `${entry.color}38` },
                { offset: 1, color: `${entry.color}00` }
              ])
            }
      }))
    }),
    [labels, series, theme, showLegend]
  );
  return <EChart option={option} height={height} />;
}

export function DonutChart({
  data,
  height = 240,
  centerLabel,
  centerValue
}: {
  data: { name: string; value: number; color: string }[];
  height?: number;
  centerLabel?: string;
  centerValue?: string | number;
}) {
  const theme = useChartTheme();
  const total = data.reduce((sum, entry) => sum + entry.value, 0);
  const option = useMemo<echarts.EChartsCoreOption>(
    () => ({
      backgroundColor: "transparent",
      animationDuration: 700,
      tooltip: {
        trigger: "item",
        backgroundColor: theme.tooltipBg,
        borderColor: theme.tooltipBorder,
        textStyle: { color: theme.strongText, fontSize: 11 },
        formatter: "{b}: {c} ({d}%)"
      },
      legend: {
        bottom: 0,
        left: "center",
        icon: "circle",
        itemWidth: 6,
        itemHeight: 6,
        itemGap: 14,
        textStyle: { color: theme.text, fontSize: 10 },
        formatter: (name: string) => name
      },
      graphic: [
        {
          type: "text",
          left: "center",
          top: "38%",
          style: {
            text: String(centerValue ?? total),
            fill: theme.strongText,
            fontSize: 28,
            fontWeight: 600,
            fontFamily: "Space Grotesk, sans-serif",
            textAlign: "center"
          }
        },
        {
          type: "text",
          left: "center",
          top: "49%",
          style: {
            text: centerLabel || "",
            fill: theme.text,
            fontSize: 10,
            fontFamily: "Space Grotesk, sans-serif",
            textAlign: "center"
          }
        }
      ],
      series: [
        {
          type: "pie",
          radius: ["58%", "78%"],
          center: ["50%", "43%"],
          avoidLabelOverlap: true,
          padAngle: 2,
          itemStyle: { borderRadius: 4, borderColor: theme.panel, borderWidth: 2 },
          label: { show: false },
          emphasis: { scaleSize: 5 },
          data: data.map((entry) => ({
            name: entry.name,
            value: entry.value,
            itemStyle: { color: entry.color }
          }))
        }
      ]
    }),
    [data, theme, total, centerLabel, centerValue]
  );
  return <EChart option={option} height={height} />;
}

export function BarChart({
  labels,
  values,
  color = "#8b5cf6",
  height = 230,
  horizontal = false
}: {
  labels: string[];
  values: number[];
  color?: string;
  height?: number;
  horizontal?: boolean;
}) {
  const theme = useChartTheme();
  const option = useMemo<echarts.EChartsCoreOption>(() => {
    const categoryAxis = {
      type: "category" as const,
      data: labels,
      axisLine: { lineStyle: { color: theme.line } },
      axisTick: { show: false },
      axisLabel: { color: theme.text, fontSize: 9, width: 90, overflow: "truncate" as const }
    };
    const valueAxis = {
      type: "value" as const,
      minInterval: 1,
      splitLine: { lineStyle: { color: theme.line, type: "dashed" as const } },
      axisLabel: { color: theme.text, fontSize: 9 }
    };
    return {
      backgroundColor: "transparent",
      animationDuration: 600,
      grid: { left: horizontal ? 90 : 12, right: 16, top: 14, bottom: 8, containLabel: !horizontal },
      tooltip: {
        trigger: "axis",
        backgroundColor: theme.tooltipBg,
        borderColor: theme.tooltipBorder,
        textStyle: { color: theme.strongText, fontSize: 11 },
        axisPointer: { type: "shadow" }
      },
      xAxis: horizontal ? valueAxis : categoryAxis,
      yAxis: horizontal ? categoryAxis : valueAxis,
      series: [
        {
          type: "bar",
          data: values,
          barMaxWidth: 22,
          itemStyle: {
            borderRadius: horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0],
            color: new echarts.graphic.LinearGradient(horizontal ? 0 : 0, horizontal ? 0 : 0, horizontal ? 1 : 0, horizontal ? 0 : 1, [
              { offset: 0, color },
              { offset: 1, color: `${color}55` }
            ])
          }
        }
      ]
    };
  }, [labels, values, color, theme, horizontal]);
  return <EChart option={option} height={height} />;
}
