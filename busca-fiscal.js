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

    function casaItemLc(campo, termo) {
        var codCampo = codigoDoCampo(campo);
        if (codCampo === null) return false;
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

    // Filtra as linhas da base. Termo vazio devolve a base inteira.
    function filtrar(dados, termo, modo) {
        if (!dados || !dados.length) return [];
        termo = String(termo == null ? '' : termo);
        if (!termo.trim()) return dados;
        var campos = CAMPOS_POR_MODO[modo] || CAMPOS_POR_MODO.all;
        return dados.filter(function (linha) {
            return campos.some(function (c) { return casaCampo(linha[c[0]], termo, c[1]); });
        });
    }

    var api = { filtrar: filtrar, MODOS: MODOS, CAMPOS: CAMPOS };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else raiz.BuscaFiscal = api;
})(typeof window !== 'undefined' ? window : this);
