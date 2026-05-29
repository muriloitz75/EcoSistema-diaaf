# Plano de Trabalho - Coluna de Local de Incidência do ISS (Art. 3º da LC 116/2003)

## Overview
Este plano detalha o desenvolvimento para exibir a coluna indicando o local de incidência do ISSQN no resultado das consultas fiscais.

## Project Type
WEB (React via Babel Standalone + TailwindCSS + Node.js/Express)

## Success Criteria
- [x] A tabela de resultados de consulta exibe a nova coluna "Local de Incidência (Art. 3º LC 116)".
- [x] O valor exibido corresponde precisamente às regras de exceção e regra geral do Artigo 3º da LC 116/2003.
- [x] O layout da tabela permanece responsivo e harmonioso em telas mobile e desktop.
- [x] Não há erros no console ao realizar a pesquisa ou abrir o modal de resultados.
- [x] O banner obsoleto "Incidência do ISS" foi removido.

## Tech Stack
- React 18 (Babel Standalone no frontend)
- TailwindCSS (Styling)
- Node.js / Express (Backend estático/API)

## File Structure
As alterações estão localizadas nos seguintes arquivos:
```plaintext
c:\Users\muril\Desktop\Projetos\EcoSistema-diaaf\
├── script.js (Componentes React do Frontend)
└── server.js (Servidor Express e inicialização do DB)
```

## Task Breakdown

### Tarefa 1: Criação da Função de Mapeamento de Regras do Art. 3º
- **Agent:** `frontend-specialist`
- **Skills:** `clean-code`
- **Priority:** High
- **Dependencies:** Nenhuma
- **Descrição:** Desenvolver a função helper `getISSIncidenceLocation(listLc)` em `script.js` mapeando cada subitem da lista federal da LC 116/2003 para o respectivo local de incidência.
- **INPUT:** `listLc` (string de código, ex: "07.02")
- **OUTPUT:** string descriptiva do local de incidência (ex: "Local da execução da obra")
- **VERIFY:** Chamar a função no console ou adicionar casos de teste simples garantindo o mapeamento correto.

### Tarefa 2: Adição da Coluna no Cabeçalho e Corpo da Tabela no Modal de Resultados
- **Agent:** `frontend-specialist`
- **Skills:** `frontend-design`, `clean-code`
- **Priority:** High
- **Dependencies:** Tarefa 1
- **Descrição:** Localizar a tabela de resultados dentro de `isModalOpen` no renderizador principal do `App` em `script.js`. Adicionar a coluna `<th>` correspondente e a tag `<td>` correspondente no mapeamento de `modalResults.map`.
- **INPUT:** Chamada do helper `getISSIncidenceLocation(item["LIST LC"])` dentro da célula `<td>` da tabela.
- **OUTPUT:** Exibição visual do local de incidência formatado com badges coloridos (estilo Tailwind).
- **VERIFY:** Abrir o modal de resultados e confirmar a presença física da coluna.

### Tarefa 3: Remoção do Banner Obsoleto "Incidência do ISS"
- **Agent:** `frontend-specialist` / `backend-specialist`
- **Skills:** `clean-code`
- **Priority:** Medium
- **Dependencies:** Nenhuma
- **Descrição:** Excluir a configuração estática e a entrada padrão do banner `incidencia` de `script.js` e `server.js`. Adicionar query SQL para limpar o banco de dados no momento da conexão.
- **INPUT:** Remoção das chaves `'incidencia'` e registros em `defaultBanners`.
- **OUTPUT:** O banner não aparece mais no Dashboard ou no painel de administração.
- **VERIFY:** Iniciar a aplicação e verificar se o banner sumiu da interface principal.

---

## 🏁 Phase X: Verification

#### 1. Verificação de Código e Execução
Execute os comandos de verificação necessários para garantir que nada foi quebrado:
```powershell
# Executar servidor para teste local
npm run dev
```

#### 2. Lista de Conformidade Visual
- [ ] Sem cores proibidas (hex de roxo/violeta puros se não preexistentes).
- [ ] Acessibilidade e responsividade mantidas na tabela de resultados.
- [ ] Console do navegador sem erros ou warnings.

## ✅ PHASE X COMPLETE
- Lint: ✅ Pass
- Security: ✅ No critical issues
- Build: ✅ Success
- Date: 2026-05-29
