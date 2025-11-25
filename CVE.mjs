#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'

const root = process.argv[2] || '.'
const listPath = process.argv[3] || path.join(process.cwd(), 'vulnerabilities.txt')

// -----------------------------------------------------------------------------
// Carrega a lista de pacotes vulneráveis
// -----------------------------------------------------------------------------
if (!fs.existsSync(listPath)) {
  console.error(`❌ Lista de pacotes vulneráveis não encontrada: ${listPath}`)
  process.exit(2)
}

const listText = fs.readFileSync(listPath, 'utf8')
const vulnerablePackages = new Set(
  listText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
)

// -----------------------------------------------------------------------------
// Busca recursiva por lockfiles
// -----------------------------------------------------------------------------
function findLockfiles(startDir) {
  const results = []

  function walk(dir) {
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name)

      if (entry.isDirectory()) {
        // ignora node_modules (não adianta varrer aqui)
        if (entry.name === 'node_modules') continue
        walk(full)
      } else {
        if (
          entry.name === 'package-lock.json' ||
          entry.name === 'yarn.lock' ||
          entry.name === 'pnpm-lock.yaml'
        ) {
          results.push(full)
        }
      }
    }
  }

  walk(startDir)
  return results
}

const lockfiles = findLockfiles(root)

if (lockfiles.length === 0) {
  console.log('❌ Nenhum lockfile encontrado (package-lock.json, yarn.lock ou pnpm-lock.yaml)')
  process.exit(3)
}

// -----------------------------------------------------------------------------
// Função para coletar pacotes de package-lock.json
// -----------------------------------------------------------------------------
function extractFromPackageLock(lock) {
  const names = new Set()

  if (lock.packages && typeof lock.packages === 'object') {
    for (const key of Object.keys(lock.packages)) {
      if (key.startsWith('node_modules/')) {
        names.add(key.replace('node_modules/', ''))
      }
    }
  }

  if (lock.dependencies) {
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps)) {
        names.add(name)
        if (info?.dependencies) walk(info.dependencies)
      }
    }
    walk(lock.dependencies)
  }

  return names
}

// -----------------------------------------------------------------------------
// Função para coletar pacotes de yarn.lock (v1)
// -----------------------------------------------------------------------------
function extractFromYarnLock(text) {
  const names = new Set()
  const lines = text.split(/\r?\n/)

  for (const l of lines) {
    const match = l.match(/^"?(.*?)@/)
    if (match) {
      const pkg = match[1]
      if (pkg && !pkg.startsWith('npm:')) {
        names.add(pkg)
      }
    }
  }
  return names
}

// -----------------------------------------------------------------------------
// Função para coletar pacotes de pnpm-lock.yaml (versões recentes)
// -----------------------------------------------------------------------------
function extractFromPnpmLock(text) {
  const names = new Set()
  const lines = text.split(/\r?\n/)

  for (const l of lines) {
    const match = l.match(/^\s*([-a-zA-Z0-9_@/]+):/)
    if (match) {
      names.add(match[1])
    }
  }
  return names
}

// -----------------------------------------------------------------------------
// Execução por lockfile
// -----------------------------------------------------------------------------
let totalHits = 0

for (const file of lockfiles) {
  console.log(`\n🔍 Verificando: ${file}`)

  const ext = path.basename(file)

  let installed = new Set()

  try {
    if (ext === 'package-lock.json') {
      const json = JSON.parse(fs.readFileSync(file, 'utf8'))
      installed = extractFromPackageLock(json)
    } else if (ext === 'yarn.lock') {
      const content = fs.readFileSync(file, 'utf8')
      installed = extractFromYarnLock(content)
    } else if (ext === 'pnpm-lock.yaml') {
      const content = fs.readFileSync(file, 'utf8')
      installed = extractFromPnpmLock(content)
    }
  } catch (err) {
    console.error(`❌ Erro ao ler ${file}`, err)
    continue
  }

  const hits = [...installed].filter((p) => vulnerablePackages.has(p))

  if (hits.length > 0) {
    totalHits += hits.length
    console.log('⚠️  Pacotes suspeitos encontrados:')
    hits.sort().forEach((h) => console.log(` - ${h}`))
  } else {
    console.log('✅ Nenhum pacote suspeito encontrado nesse lockfile')
  }
}

// resumo final
console.log('\n--------------------------------------------------------')
if (totalHits > 0) {
  console.log(`⚠️  Encontrados ${totalHits} pacotes suspeitos no total.`)
  process.exitCode = 1
} else {
  console.log('🎉 Nenhum pacote suspeito encontrado em nenhum lockfile.')
}
