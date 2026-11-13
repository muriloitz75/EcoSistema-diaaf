"""Gera lista-nacional.json a partir dos anexos oficiais da NFS-e Nacional.

Fontes (gov.br/nfse > Biblioteca > Documentação técnica), salvas em fontes/:
  - Anexo B  (documentação atual): ANEXO_B-NBS2-LISTA_SERVICO_NACIONAL-SNNFSe, aba "LISTA.SERV.NAC."
      Códigos de tributação nacional de 6 dígitos (item.subitem.desdobro), ex.:
      07.02 -> 07.02.01 e 07.02.02.
  - Anexo VIII (RTC): tabela de correlação Item de Serviço x NBS x cClassTrib x cIndOp, aba "tabela geral"
      NBS correlacionadas a cada SUBITEM (não ao desdobramento) e a atividade do Simples
      Nacional (PGDAS-D: Anexo III, IV, Fator R ou impeditiva). Quando um subitem tem mais de
      uma atividade, cada uma vale para o grupo de NBS que vem abaixo dela na planilha.
      A própria RFB avisa que é trabalho inicial, sem regra de negócio no emissor; por isso o
      JSON leva avisos.

  - Resolução CGSN nº 140/2018 (Simples Nacional), texto vigente no portal Normas da RFB
    (normasinternet2.receita.fazenda.gov.br, ato 92278), anexos em PDF:
      Anexo VI  - CNAEs impeditivos ao Simples (redação da Res. CGSN nº 143/2018)
                  api/consulta-externa/ato/92278/anexo/50966
      Anexo VII - CNAEs ambíguos: abrangem atividade impeditiva e permitida
                  (redação da Res. CGSN nº 156/2020)
                  api/consulta-externa/ato/92278/anexo/58338
    Norma oficial em vigor (não é correlação preliminar). Vale por CNAE.

Uso (quando sair nova versão de um anexo, salve o arquivo em fontes/ e rode):
    npm run dados:lista-nacional
    python tools/importar_lista_nacional.py [--anexo-b ARQ.xlsx] [--anexo-viii ARQ.xlsx]
                                            [--cgsn-vi ARQ.pdf] [--cgsn-vii ARQ.pdf]

Sem argumentos, usa o arquivo mais recente de cada anexo em fontes/
(anexo_b-*.xlsx, anexo_viii-*.xlsx, resolucao_cgsn_140_*anexo_vi_*.pdf e
resolucao_cgsn_140_*anexo_vii_*.pdf). Só o Anexo B é obrigatório.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parents[1]
SAIDA = ROOT / "lista-nacional.json"
ABA_ANEXO_B = "LISTA.SERV.NAC."
ABA_ANEXO_VIII = "tabela geral"
AVISO_NBS = (
    "Correlação preliminar: Anexo VIII da NFS-e (RFB/CGNFS-e) é trabalho inicial, em desenvolvimento, "
    "sem regra de negócio no emissor. As NBS são correlacionadas ao subitem, não ao desdobramento."
)
AVISO_SN = (
    "Correlação preliminar do Anexo VIII da NFS-e (RFB/CGNFS-e), sem regra de negócio no emissor. "
    "Confirme o enquadramento na LC 123/2006 (art. 18, §§ 5º-B a 5º-I e 5º-J/5º-M - Fator R) "
    "e na Resolução CGSN nº 140/2018."
)


def rotulo_sn(descricao: str) -> str:
    """Rótulo curto da atividade do Simples a partir da descrição oficial."""
    d = descricao.lower()
    if "impeditiva" in d:
        return "Impeditiva ao Simples"
    if "fator" in d:
        return "Anexo III ou V (Fator R)"
    anexos = re.findall(r"anexo\s+(iii|iv|v)\b", d)
    return f"Anexo {anexos[-1].upper()}" if anexos else descricao[:40]


def mais_recente(padrao: str):
    candidatas = sorted((ROOT / "fontes").glob(padrao))
    return candidatas[-1] if candidatas else None


def abrir_aba(planilha: Path, aba: str):
    wb = load_workbook(planilha, read_only=True, data_only=True)
    if aba not in wb.sheetnames:
        sys.exit(f'Aba "{aba}" não encontrada em {planilha.name}. Abas: {wb.sheetnames}')
    return list(wb[aba].iter_rows(values_only=True))[1:]


def ler_anexo_b(planilha: Path):
    subitens, codigos = {}, []
    for linha in abrir_aba(planilha, ABA_ANEXO_B):
        codigo, item, subitem, desdobro, descricao = (list(linha) + [None] * 5)[:5]
        if item is None:
            continue
        item, subitem, desdobro = int(item), int(subitem), int(desdobro)
        descricao = " ".join(str(descricao or "").split())
        if subitem == 0:
            continue  # linha de título do item
        if desdobro == 0:
            subitens[(item, subitem)] = descricao
            continue
        if codigo is None or int(codigo) != item * 10000 + subitem * 100 + desdobro:
            sys.exit(f"Código nacional incoerente na linha {item}.{subitem}.{desdobro}: {codigo!r}")
        codigos.append((item, subitem, desdobro, descricao))
    return [
        {
            "codigo": f"{i:02d}.{s:02d}.{d:02d}",
            "codigoNacional": f"{i:02d}{s:02d}{d:02d}",
            "subitem": f"{i:02d}.{s:02d}",
            "descricao": desc,
            "descricaoSubitem": subitens.get((i, s), ""),
        }
        for i, s, d, desc in sorted(codigos)
    ]


def ler_anexo_viii(planilha: Path):
    """NBS e atividade do Simples por subitem.

    A coluna de item só vem preenchida na 1ª linha de cada grupo; a atividade do Simples
    (COD_ATIV_SN) vale para as NBS seguintes até aparecer outra ou mudar o subitem.
    """
    nbs_por_subitem, sn_por_subitem, atividades = {}, {}, {}
    ignorados, item, sn = set(), None, None
    for linha in abrir_aba(planilha, ABA_ANEXO_VIII):
        item_lc, _desc_item, nbs, desc_nbs, cod_sn, desc_sn = (list(linha) + [None] * 6)[:6]
        if item_lc is not None:
            item, sn = str(item_lc).strip(), None
        if item is None:
            continue
        if not re.fullmatch(r"\d{2}\.\d{2}", item):
            ignorados.add(item)  # ex.: 99.02.01 (códigos da RTC ainda fora do Anexo B)
            continue
        if cod_sn is not None:
            sn = str(cod_sn).strip()
            descricao = " ".join(str(desc_sn or "").split())
            atividades[sn] = {"descricao": descricao, "rotulo": rotulo_sn(descricao)}
            codigos_sn = sn_por_subitem.setdefault(item, [])
            if sn not in codigos_sn:
                codigos_sn.append(sn)
        if nbs is None:
            continue
        lista = nbs_por_subitem.setdefault(item, [])
        nbs = str(nbs).strip()
        if all(n["codigo"] != nbs for n in lista):
            lista.append({"codigo": nbs, "descricao": " ".join(str(desc_nbs or "").split()), "sn": sn})

    def chave_sn(c):
        return (0, int(c)) if c.isdigit() else (1, c)

    return {
        "nbs": dict(sorted(nbs_por_subitem.items())),
        "snPorSubitem": dict(sorted(sn_por_subitem.items())),
        "atividadesSn": dict(sorted(atividades.items(), key=lambda kv: chave_sn(kv[0]))),
        "ignorados": sorted(ignorados),
    }


CNAE_RE = re.compile(r"\b(\d{4}-\d/\d{2})\b")
CABECALHO_RE = re.compile(r"^(ANEXO |Subclasse|Códigos previstos)", re.I)


def ler_cnaes_cgsn(pdf: Path) -> dict:
    """{CNAE: denominação} de um anexo da Res. CGSN 140 em PDF.

    A denominação pode quebrar em várias linhas e, às vezes, a extração junta vários
    CNAEs na mesma linha; por isso o texto é cortado em cada código, onde quer que esteja.
    """
    from pypdf import PdfReader

    texto = "\n".join((p.extract_text() or "") for p in PdfReader(str(pdf)).pages)
    linhas = [" ".join(l.split()) for l in texto.splitlines()]
    corrido = " ".join(l for l in linhas if l and not CABECALHO_RE.match(l))
    partes = CNAE_RE.split(corrido)  # [antes, cnae1, denom1, cnae2, denom2, ...]
    cnaes = {}
    for cnae, denominacao in zip(partes[1::2], partes[2::2]):
        if cnae in cnaes:
            sys.exit(f"CNAE repetido em {pdf.name}: {cnae}")
        cnaes[cnae] = denominacao.strip().capitalize()
    if not cnaes:
        sys.exit(f"Nenhum CNAE encontrado em {pdf.name}")
    vistos = set(CNAE_RE.findall(texto))
    if vistos != set(cnaes):
        sys.exit(f"{pdf.name}: códigos no texto ({len(vistos)}) diferem dos lidos ({len(cnaes)})")
    return dict(sorted(cnaes.items()))


def main():
    args = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    args.add_argument("--anexo-b", type=Path, default=None)
    args.add_argument("--anexo-viii", type=Path, default=None)
    args.add_argument("--cgsn-vi", type=Path, default=None)
    args.add_argument("--cgsn-vii", type=Path, default=None)
    opcoes = args.parse_args()

    anexo_b = opcoes.anexo_b or mais_recente("anexo_b-*.xlsx")
    if not anexo_b:
        sys.exit("Nenhuma planilha anexo_b-*.xlsx em fontes/. Informe com --anexo-b.")
    anexo_viii = opcoes.anexo_viii or mais_recente("anexo_viii-*.xlsx")
    cgsn_vi = opcoes.cgsn_vi or mais_recente("resolucao_cgsn_140_*anexo_vi_*.pdf")
    cgsn_vii = opcoes.cgsn_vii or mais_recente("resolucao_cgsn_140_*anexo_vii_*.pdf")

    codigos = ler_anexo_b(anexo_b)
    saida = {
        "fonte": anexo_b.name,
        "descricao": "Lista de Serviços Nacional da NFS-e (Anexo B): códigos de tributação nacional",
        "codigos": codigos,
    }

    por_subitem = {}
    for c in codigos:
        por_subitem[c["subitem"]] = por_subitem.get(c["subitem"], 0) + 1
    desdobrados = sum(1 for n in por_subitem.values() if n > 1)
    print(f"Anexo B ({anexo_b.name}): {len(codigos)} códigos, {len(por_subitem)} subitens ({desdobrados} desdobrados)")

    if anexo_viii:
        viii = ler_anexo_viii(anexo_viii)
        nbs, sn = viii["nbs"], viii["snPorSubitem"]
        saida["nbs"] = {"fonte": anexo_viii.name, "aviso": AVISO_NBS, "porSubitem": nbs}
        saida["simplesNacional"] = {
            "fonte": anexo_viii.name,
            "aviso": AVISO_SN,
            "atividades": viii["atividadesSn"],
            "porSubitem": sn,
        }
        print(f"Anexo VIII ({anexo_viii.name}): {sum(len(v) for v in nbs.values())} pares subitem x NBS em {len(nbs)} subitens")
        print(f"  Subitens nacionais sem NBS: {sorted(set(por_subitem) - set(nbs)) or 'nenhum'}")
        print(f"  Simples Nacional: {len(sn)} subitens classificados, "
              f"{sum(1 for v in sn.values() if len(v) > 1)} com mais de uma atividade")
        for cod, a in viii["atividadesSn"].items():
            print(f"    {cod:>3} {a['rotulo']:<26} {sum(1 for v in sn.values() if cod in v):>3} subitens")
        print(f"  Subitens nacionais sem atividade do Simples: {sorted(set(por_subitem) - set(sn)) or 'nenhum'}")
        print(f"  Ignorados (não são subitem dd.dd): {viii['ignorados'] or 'nenhum'}")
    else:
        print("Anexo VIII não encontrado em fontes/: lista gerada sem NBS.")

    if cgsn_vi and cgsn_vii:
        impeditivos, ambiguos = ler_cnaes_cgsn(cgsn_vi), ler_cnaes_cgsn(cgsn_vii)
        if set(impeditivos) & set(ambiguos):
            sys.exit(f"CNAE nos dois anexos: {sorted(set(impeditivos) & set(ambiguos))}")
        saida["cnaeSimples"] = {
            "fonte": "Resolução CGSN nº 140/2018 (vigente): Anexo VI, redação da Res. CGSN nº 143/2018; "
                     "Anexo VII, redação da Res. CGSN nº 156/2020",
            "arquivos": [cgsn_vi.name, cgsn_vii.name],
            "impeditivos": impeditivos,
            "ambiguos": ambiguos,
        }
        print(f"Res. CGSN 140: {len(impeditivos)} CNAEs impeditivos (Anexo VI), {len(ambiguos)} ambíguos (Anexo VII)")
        dados = ROOT / "dados.json"
        if dados.exists():
            base = {r["CNAE"] for r in json.loads(dados.read_text(encoding="utf-8"))}
            print(f"  Na base municipal: {len(base & set(impeditivos))} impeditivos e "
                  f"{len(base & set(ambiguos))} ambíguos, de {len(base)} CNAEs")
    else:
        print("Anexos VI/VII da Res. CGSN 140 não encontrados em fontes/: lista gerada sem eles.")

    SAIDA.write_text(json.dumps(saida, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Gravado {SAIDA.name}")

    dados = ROOT / "dados.json"
    if dados.exists():
        municipais = {r["LIST LC"] for r in json.loads(dados.read_text(encoding="utf-8"))}
        print(f"Subitens só na lista nacional (sem CNAE/alíquota municipal): {sorted(set(por_subitem) - municipais) or 'nenhum'}")
        print(f"Subitens só na base municipal (sem código nacional): {sorted(municipais - set(por_subitem)) or 'nenhum'}")


if __name__ == "__main__":
    main()
