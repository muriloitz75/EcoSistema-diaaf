// Busca na base ISS / CNAE (dados.json).
//
// Fonte única das regras de busca, usada pela tela "Consulta ISS / CNAE" (navegador)
// e pela rota /api/fiscal/search (servidor). Para mudar como a busca funciona,
// altere só este arquivo.
//
// Script comum (sem import/export), pelo mesmo motivo do incidencia-iss.js:
//   - navegador: carregado por <script> no index.html → window.BuscaFiscal
//   - Node:      require('./busca-fiscal') → { filtrar, MODOS, CAMPOS }
//
// Regras:
//   - Termo com letras → procura o texto nas descrições (sem acento e sem maiúsculas).
//   - Termo só com números e . - / → é um código:
//       Item LC: "7.02" só o 7.02; "7" ou "7." todos os subitens do item 7.
//                Código de tributação nacional da NFS-e ("07.02.01", "070201" ou
//                "70201") → o subitem dele (07.02), pois CNAE e alíquota municipais
//                são definidos por subitem (Resolução SEFAZGO nº 01/2021).
//       NBS:     "1.0101.11.00" (ou começo dele, "1.0101") → subitens com essa NBS no
//                Anexo VIII (correlação preliminar). Só no modo "all" e só com lista nacional.
//       CNAE:    começo do código, ignorando - / e espaços ("8640", "8640-2/02").
//                O ponto também é ignorado quando o termo tem - ou / (formato IBGE,
//                "62.01-5"). Um termo só com ponto ("7.02") é tratado como item LC.
(function (raiz) {
    'use strict';

    var CAMPOS = {
        itemLc: 'LIST LC',
        descricaoItemLc: 'Descrição item da lista da Lei Complementar nº 001/2003 - CTM',
        cnae: 'CNAE',
        descricaoCnae: 'Descrição do CNAE',
        aliquota: 'Alíquota'
    };

    // Campos consultados em cada modo e o tipo de comparação de cada um.
    var CAMPOS_POR_MODO = {
        all: [[CAMPOS.itemLc, 'lc'], [CAMPOS.descricaoItemLc, 'texto'], [CAMPOS.cnae, 'cnae'], [CAMPOS.descricaoCnae, 'texto']],
        text: [[CAMPOS.descricaoItemLc, 'texto'], [CAMPOS.descricaoCnae, 'texto']],
        lc: [[CAMPOS.itemLc, 'lc']],
        cnae: [[CAMPOS.cnae, 'cnae']]
    };
    var MODOS = Object.keys(CAMPOS_POR_MODO);

    function normalizarTexto(t) {
        if (!t) return '';
        return String(t).trim().toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    }

    function ehCodigo(termo) {
        return /^[\d\-\/.]+$/.test(termo.trim());
    }

    // Tira zeros à esquerda de cada parte: "07.02" → "7.02", "007" → "7".
    function normalizarCodigo(c) {
        var s = String(c).trim();
        if (s.indexOf('.') !== -1) {
            return s.split('.').map(function (p) { return p.replace(/^0+/, '') || '0'; }).join('.');
        }
        return s.replace(/^0+/, '') || '0';
    }

    // Código no início do campo (ex.: "07.02 - Obras..." → "07.02").
    function codigoDoCampo(campoNormalizado) {
        var m = campoNormalizado.match(/^([\d.\-\/]+)/);
        return m ? normalizarCodigo(m[1]) : null;
    }

    // Código de tributação nacional da NFS-e no termo → "07.02.01" (ou null se não for um).
    // Aceita "07.02.01", "7.2.1", "070201" e "70201" (a planilha oficial omite o zero inicial).
    function codigoNacional(termo) {
        var t = String(termo == null ? '' : termo).trim();
        var m = t.match(/^(\d{1,2})\.(\d{1,2})\.(\d{1,2})$/) || t.match(/^(\d{1,2})(\d{2})(\d{2})$/);
        if (!m) return null;
        var dois = function (n) { return ('0' + parseInt(n, 10)).slice(-2); };
        return dois(m[1]) + '.' + dois(m[2]) + '.' + dois(m[3]);
    }

    function casaItemLc(campo, termo) {
        var codCampo = codigoDoCampo(campo);
        if (codCampo === null) return false;
        var nacional = codigoNacional(termo);
        if (nacional) termo = nacional.slice(0, 5); // "07.02.01" → subitem "07.02"
        var codTermo = normalizarCodigo(termo);
        if (codCampo === codTermo) return true;

        // "7." ou "7" → todos os subitens do item 7 (e só dele: não pega 70, 71...).
        var item = null;
        if (termo.slice(-1) === '.') item = codTermo.slice(0, -1);
        else if (termo.indexOf('.') === -1) item = codTermo;
        return item !== null && codCampo.indexOf(item + '.') === 0;
    }

    function casaCnae(campo, termo) {
        var formatoIbge = /[\-\/]/.test(termo);
        var limpar = function (s) { return s.replace(formatoIbge ? /[\s\-\/.]/g : /[\s\-\/]/g, ''); };
        return limpar(campo).indexOf(limpar(termo)) === 0;
    }

    // Termo-código comparado a um campo de descrição: só casa se a descrição
    // começar exatamente por esse código.
    function casaCodigoNoInicio(campo, termo) {
        var codCampo = codigoDoCampo(campo);
        return codCampo !== null && codCampo === normalizarCodigo(termo);
    }

    function casaCampo(valor, termo, tipo) {
        if (!valor || !termo) return false;
        var campo = normalizarTexto(valor);
        var t = normalizarTexto(termo);

        if (!ehCodigo(termo)) return campo.indexOf(t) !== -1;
        if (tipo === 'lc') return casaItemLc(campo, t);
        if (tipo === 'cnae') return casaCnae(campo, t);
        return casaCodigoNoInicio(campo, t);
    }

    // NBS no termo → "1.0101.11.00" ou um começo válido ("1.0101", "1.0101.1"); senão null.
    // O 2º segmento tem 4 dígitos, o que não se confunde com item LC ("7.02") nem CNAE.
    function codigoNbs(termo) {
        var t = String(termo == null ? '' : termo).trim();
        return /^\d\.\d{4}(\.\d{1,2}(\.\d{1,2})?)?$/.test(t) ? t : null;
    }

    // "7.2" / "07.02" → "07.02" (chave dos mapas por subitem de lista-nacional.json).
    function chaveSubitem(subitem) {
        var p = String(subitem).trim().split('.');
        return ('0' + parseInt(p[0], 10)).slice(-2) + '.' + ('0' + parseInt(p[1], 10)).slice(-2);
    }

    // NBS correlacionadas a um subitem no Anexo VIII (lista-nacional.json → nbs.porSubitem).
    // Cada NBS traz `sn`: o código da atividade do Simples Nacional que vale para ela.
    function nbsDoSubitem(listaNacional, subitem) {
        var mapa = listaNacional && listaNacional.nbs && listaNacional.nbs.porSubitem;
        if (!mapa || subitem == null) return [];
        return mapa[chaveSubitem(subitem)] || [];
    }

    // Atividades do Simples Nacional (PGDAS-D) de um subitem no Anexo VIII:
    // [{ codigo: '13', rotulo: 'Anexo IV', descricao: '...' }]. Mais de uma = depende da NBS.
    function simplesDoSubitem(listaNacional, subitem) {
        var sn = listaNacional && listaNacional.simplesNacional;
        if (!sn || subitem == null) return [];
        return (sn.porSubitem[chaveSubitem(subitem)] || []).map(function (cod) {
            var a = sn.atividades[cod] || {};
            return { codigo: cod, rotulo: a.rotulo || cod, descricao: a.descricao || '' };
        });
    }

    // Subitens ("07.02") que têm alguma NBS começando pelo termo.
    function subitensDaNbs(listaNacional, nbs) {
        var mapa = (listaNacional && listaNacional.nbs && listaNacional.nbs.porSubitem) || {};
        return Object.keys(mapa).filter(function (s) {
            return mapa[s].some(function (n) { return n.codigo.indexOf(nbs) === 0; });
        });
    }

    // Filtra as linhas da base. Termo vazio devolve a base inteira.
    // listaNacional (opcional) habilita a busca por NBS.
    function filtrar(dados, termo, modo, listaNacional) {
        if (!dados || !dados.length) return [];
        termo = String(termo == null ? '' : termo);
        if (!termo.trim()) return dados;

        var nbs = codigoNbs(termo);
        if (nbs && (modo || 'all') === 'all' && listaNacional) {
            var alvo = subitensDaNbs(listaNacional, nbs).map(normalizarCodigo);
            return dados.filter(function (linha) {
                return alvo.indexOf(normalizarCodigo(String(linha[CAMPOS.itemLc]))) !== -1;
            });
        }

        var campos = CAMPOS_POR_MODO[modo] || CAMPOS_POR_MODO.all;
        return dados.filter(function (linha) {
            return campos.some(function (c) { return casaCampo(linha[c[0]], termo, c[1]); });
        });
    }

    // Códigos de tributação nacional (lista-nacional.json) de um subitem municipal.
    // listaNacional = conteúdo de lista-nacional.json ({ codigos: [...] }) ou a própria lista.
    function desdobramentos(listaNacional, subitem) {
        var codigos = (listaNacional && listaNacional.codigos) || listaNacional || [];
        var alvo = normalizarCodigo(String(subitem == null ? '' : subitem));
        return codigos.filter(function (c) { return normalizarCodigo(c.subitem) === alvo; });
    }

    // Situação de um CNAE no Simples Nacional pela Res. CGSN nº 140/2018 (norma em vigor):
    //   { situacao: 'impeditivo', anexo: 'VI', denominacao }  - Anexo VI
    //   { situacao: 'ambiguo',    anexo: 'VII', denominacao } - Anexo VII (impeditiva e permitida)
    //   { situacao: 'nao-impeditivo' }                        - não consta em nenhum dos dois
    //   null                                                   - anexos não carregados
    function simplesDoCnae(listaNacional, cnae) {
        var ref = listaNacional && listaNacional.cnaeSimples;
        if (!ref || cnae == null) return null;
        var digitos = String(cnae).replace(/\D/g, '');
        if (digitos.length !== 7) return null;
        var c = digitos.slice(0, 4) + '-' + digitos.slice(4, 5) + '/' + digitos.slice(5);
        if (ref.impeditivos[c]) return { situacao: 'impeditivo', anexo: 'VI', denominacao: ref.impeditivos[c] };
        if (ref.ambiguos[c]) return { situacao: 'ambiguo', anexo: 'VII', denominacao: ref.ambiguos[c] };
        return { situacao: 'nao-impeditivo' };
    }

    var api = {
        filtrar: filtrar,
        desdobramentos: desdobramentos,
        codigoNacional: codigoNacional,
        nbsDoSubitem: nbsDoSubitem,
        simplesDoSubitem: simplesDoSubitem,
        simplesDoCnae: simplesDoCnae,
        codigoNbs: codigoNbs,
        MODOS: MODOS,
        CAMPOS: CAMPOS
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else raiz.BuscaFiscal = api;
})(typeof window !== 'undefined' ? window : this);
