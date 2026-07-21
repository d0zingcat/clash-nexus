import React from "react"
import { createRoot } from "react-dom/client"
import { ArrowRight, Clipboard, Download, FileUp, Link2, Loader2, RotateCcw, X } from "lucide-react"

import "./index.css"
import { Button } from "./components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card"
import { Input } from "./components/ui/input"
import { Label } from "./components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs"
import { Textarea } from "./components/ui/textarea"

type Target = {
  name: string
  extension: string
}

type ConvertResponse = {
  target: string
  filename: string
  extension: string
  content: string
  warnings?: string[]
}

type Mode = "yaml" | "file" | "url"
type Source = "clash" | "loon"

function App() {
  const [targets, setTargets] = React.useState<Target[]>([])
  const [target, setTarget] = React.useState("")
  const [source, setSource] = React.useState<Source>("clash")
  const [mode, setMode] = React.useState<Mode>("yaml")
  const [yaml, setYaml] = React.useState("")
  const [url, setURL] = React.useState("")
  const [file, setFile] = React.useState<File | null>(null)
  const [result, setResult] = React.useState("")
  const [filename, setFilename] = React.useState("converted.txt")
  const [warnings, setWarnings] = React.useState<string[]>([])
  const [status, setStatus] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [qxFinalProxyChain, setQXFinalProxyChain] = React.useState(false)

  React.useEffect(() => {
    fetch("/api/targets")
      .then((response) => response.json())
      .then((data: { targets: Target[] }) => {
        setTargets(data.targets || [])
        setTarget(data.targets?.[0]?.name || "")
      })
      .catch((error: Error) => setStatus(error.message))
  }, [])

  const subscriptionLink = React.useMemo(() => {
    if (mode !== "url" || !url.trim() || !target) {
      return ""
    }
    const link = new URL("/api/subscribe", window.location.origin)
    link.searchParams.set("target", target)
    link.searchParams.set("source", source)
    link.searchParams.set("url", url.trim())
    if (target === "qx" && qxFinalProxyChain) {
      link.searchParams.set("qx_final_proxy_chain", "1")
    }
    return link.toString()
  }, [mode, qxFinalProxyChain, source, target, url])

  const visibleTargets = targets.filter((item) => source !== "loon" || item.name !== "loon")

  React.useEffect(() => {
    if (!visibleTargets.some((item) => item.name === target)) {
      setTarget(visibleTargets[0]?.name || "")
    }
  }, [source, target, visibleTargets])

  async function parseResponse(response: Response) {
    const data = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(data.error?.message || `HTTP ${response.status}`)
    }
    return data as ConvertResponse
  }

  async function convert() {
    setLoading(true)
    setStatus("转换中...")
    try {
      let response: Response
        if (mode === "file") {
        if (!file) {
          throw new Error("请选择 YAML 文件")
        }
        const form = new FormData()
          form.set("target", target)
          form.set("source", source)
        if (target === "qx" && qxFinalProxyChain) {
          form.set("qx_final_proxy_chain", "1")
        }
        form.set("file", file)
        response = await fetch("/api/convert/file", { method: "POST", body: form })
      } else {
        response = await fetch("/api/convert", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target,
            source,
            yaml: mode === "yaml" ? yaml : undefined,
            url: mode === "url" ? url.trim() : undefined,
            qxFinalProxyChain: target === "qx" && qxFinalProxyChain,
          }),
        })
      }
      const data = await parseResponse(response)
      setResult(data.content || "")
      setFilename(data.filename || "converted.txt")
      setWarnings(data.warnings || [])
      setStatus("完成")
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "转换失败")
    } finally {
      setLoading(false)
    }
  }

  async function copy(text: string, message: string) {
    await navigator.clipboard.writeText(text)
    setStatus(message)
  }

  function download() {
    const blob = new Blob([result], { type: "text/plain;charset=utf-8" })
    const objectURL = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = objectURL
    link.download = filename
    link.click()
    URL.revokeObjectURL(objectURL)
  }

  function clear() {
    setYaml("")
    setURL("")
    setFile(null)
    setResult("")
    setWarnings([])
    setStatus("")
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-6 px-5 py-8">
      <header className="flex flex-col gap-3 border-b pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Local converter</p>
          <h1 className="text-3xl font-semibold tracking-normal md:text-4xl">Clash Nexus</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Clash YAML 转换为 Stash、Loon、Egern 或 Quantumult X。支持粘贴、上传和远程 URL，并为远程配置生成可订阅的转换地址。
          </p>
        </div>
        <div className="rounded-md border px-3 py-1.5 text-xs font-medium text-muted-foreground">127.0.0.1 only</div>
      </header>

      <section className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
        <Card className="overflow-hidden">
          <CardHeader className="border-b">
            <div className="grid gap-5">
              <div>
                <CardTitle>输入</CardTitle>
                <CardDescription className="mt-1">选择来源和目标格式后转换。</CardDescription>
              </div>
              <div className="grid gap-2">
                <Label>输入格式</Label>
                <div className="grid grid-cols-2 gap-2">
                  {(["clash", "loon"] as Source[]).map((item) => <Button key={item} type="button" variant={source === item ? "default" : "outline"} onClick={() => setSource(item)}>{item === "clash" ? "Clash YAML" : "Loon"}</Button>)}
                </div>
              </div>
              <div className="grid gap-2">
                <Label>目标格式</Label>
                <div className="grid grid-cols-3 gap-2">
                  {visibleTargets.map((item) => (
                    <Button
                      key={item.name}
                      type="button"
                      variant={target === item.name ? "default" : "outline"}
                      className="justify-start"
                      onClick={() => setTarget(item.name)}
                    >
                      <span className="mr-2 capitalize">{item.name}</span>
                      <span className={target === item.name ? "text-primary-foreground/70" : "text-muted-foreground"}>{item.extension}</span>
                    </Button>
                  ))}
                </div>
              </div>
              {target === "qx" && (
                <label className="flex items-start gap-3 rounded-md border bg-muted/25 p-3 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 accent-primary"
                    checked={qxFinalProxyChain}
                    onChange={(event) => setQXFinalProxyChain(event.target.checked)}
                  />
                  <span className="grid gap-1">
                    <span className="font-medium">Final 走 Proxy Chain</span>
                    <span className="text-muted-foreground">为 QuanX final 规则追加 via-interface=%TUN%。</span>
                  </span>
                </label>
              )}
            </div>
          </CardHeader>
          <CardContent className="pt-5">
            <Tabs value={mode} onValueChange={(value) => setMode(value as Mode)}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="yaml">粘贴 YAML</TabsTrigger>
                <TabsTrigger value="file">上传文件</TabsTrigger>
                <TabsTrigger value="url">远程 URL</TabsTrigger>
              </TabsList>

              <TabsContent value="yaml">
                <div className="grid gap-2">
                  <Label htmlFor="yaml">{source === "loon" ? "Loon 配置" : "Clash YAML"}</Label>
                  <Textarea
                    id="yaml"
                    className="min-h-[430px] resize-y font-mono text-xs leading-5"
                    placeholder={source === "loon" ? "粘贴 Loon 配置" : "粘贴 Clash YAML 配置"}
                    value={yaml}
                    onChange={(event) => setYaml(event.target.value)}
                  />
                </div>
              </TabsContent>

              <TabsContent value="file">
                <div className="grid min-h-[430px] place-items-center rounded-lg border border-dashed bg-muted/35 p-8 text-center">
                  <div className="grid max-w-sm gap-4">
                    <FileUp className="mx-auto h-8 w-8 text-muted-foreground" />
                    <div>
                      <h3 className="text-base font-medium">上传{source === "loon" ? " Loon" : " YAML"}文件</h3>
                      <p className="mt-2 text-sm leading-6 text-muted-foreground">支持配置文件或纯文本。</p>
                    </div>
                    <Input type="file" accept={source === "loon" ? ".conf,text/plain" : ".yaml,.yml,text/yaml,text/plain"} onChange={(event) => setFile(event.target.files?.[0] || null)} />
                    {file && <p className="text-xs text-muted-foreground">{file.name}</p>}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="url">
                <div className="grid min-h-[430px] content-start gap-5">
                  <div className="grid gap-2">
                    <Label htmlFor="url">远程{source === "loon" ? " Loon" : " Clash"}配置 URL</Label>
                    <Input id="url" type="url" placeholder="https://example.com/clash.yaml" value={url} onChange={(event) => setURL(event.target.value)} />
                  </div>
                  <div className="rounded-lg border bg-muted/30 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <Link2 className="h-4 w-4" />
                      <h3 className="text-sm font-medium">订阅地址</h3>
                    </div>
                    <p className="mb-4 text-sm leading-6 text-muted-foreground">填到客户端订阅中，每次请求都会实时拉取远程 Clash 配置并转换。</p>
                    <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                      <Input readOnly value={subscriptionLink} placeholder="输入 URL 后生成" />
                      <Button variant="outline" disabled={!subscriptionLink} onClick={() => copy(subscriptionLink, "已复制订阅地址")}>
                        <Link2 className="mr-2 h-4 w-4" />
                        复制链接
                      </Button>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              <Button onClick={convert} disabled={loading || !target}>
                {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ArrowRight className="mr-2 h-4 w-4" />}
                转换
              </Button>
              <Button variant="outline" onClick={clear}>
                <X className="mr-2 h-4 w-4" />
                清空
              </Button>
              {status && <span className="text-sm text-muted-foreground">{status}</span>}
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="border-b">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <CardTitle>输出</CardTitle>
                <CardDescription className="mt-1">预览结果，复制内容或下载文件。</CardDescription>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" disabled={!result} onClick={() => copy(result, "已复制结果")}>
                  <Clipboard className="mr-2 h-4 w-4" />
                  复制
                </Button>
                <Button variant="outline" size="sm" disabled={!result} onClick={download}>
                  <Download className="mr-2 h-4 w-4" />
                  下载
                </Button>
                <Button variant="ghost" size="sm" disabled={!result} onClick={() => setResult("")}>
                  <RotateCcw className="mr-2 h-4 w-4" />
                  重置
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-5">
            {warnings.length > 0 && (
              <div className="mb-4 rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
                {warnings.map((warning) => (
                  <div key={warning}>{warning}</div>
                ))}
              </div>
            )}
            <Textarea
              readOnly
              className="min-h-[640px] resize-y bg-muted/20 font-mono text-xs leading-5"
              placeholder="转换结果会显示在这里"
              value={result}
            />
          </CardContent>
        </Card>
      </section>
    </main>
  )
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
