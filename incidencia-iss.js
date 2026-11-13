// Local de incidência do ISSQN — art. 3º da LC nº 116/2003.
//
// Fonte única da regra, usada pela tela "Consulta ISS / CNAE" (navegador) e pela
// rota /api/fiscal/search (servidor). Para alterar a regra, altere só este arquivo.
//
// É um script comum (sem import/export) porque o frontend roda tanto pelo bundle
// dist/app.js quanto pelo modo Babel no navegador, e nenhum dos dois resolve imports:
//   - navegador: carregado por <script> no index.html → window.IncidenciaISS
//   - Node:      require('./incidencia-iss') → { localDeIncidencia, REGRA_GERAL }
(function (raiz) {
    'use strict';

    var REGRA_GERAL = 'Estabelecimento Prestador (Regra Geral)';

    // Exceções à regra geral: o ISS é devido no domicílio do tomador / local do serviço.
    // Chave = subitem da lista sem zero à esquerda no item (ex.: "07.02" → "7.02").
    var EXCECOES = {
        '3.04': 'Domicílio do Tomador (Local dos Bens)',
        '3.05': 'Domicílio do Tomador (Local da Instalação)',
        '4.22': 'Domicílio do Tomador',
        '4.23': 'Domicílio do Tomador',
        '5.09': 'Domicílio do Tomador',
        '7.02': 'Domicílio do Tomador (Local da Obra)',
        '7.04': 'Domicílio do Tomador (Local do Serviço)',
        '7.05': 'Domicílio do Tomador (Local do Serviço)',
        '7.09': 'Domicílio do Tomador (Local do Imóvel)',
        '7.10': 'Domicílio do Tomador (Local do Imóvel)',
        '7.11': 'Domicílio do Tomador (Local da Lavra)',
        '7.12': 'Domicílio do Tomador (Local da Execução)',
        '7.14': 'Domicílio do Tomador (Local do Serviço)',
        '7.15': 'Domicílio do Tomador (Local do Serviço)',
        '7.17': 'Domicílio do Tomador (Local do Serviço)',
        '7.19': 'Domicílio do Tomador (Local da Obra)',
        '11.01': 'Domicílio do Tomador',
        '11.02': 'Domicílio do Tomador (Local dos Bens/Pessoas)',
        '11.04': 'Domicílio do Tomador (Local do Depósito)',
        '11.05': 'Domicílio do Tomador',
        '15.01': 'Domicílio do Tomador',
        '15.09': 'Domicílio do Tomador',
        '16.01': 'Domicílio do Tomador (Local do Trajeto)',
        '17.05': 'Domicílio do Tomador (Establ. do Tomador)',
        '17.10': 'Domicílio do Tomador (Local do Evento)',
        '20.01': 'Domicílio do Tomador (Local do Terminal)',
        '20.02': 'Domicílio do Tomador (Local do Terminal)',
        '20.03': 'Domicílio do Tomador (Local do Terminal)'
    };

    // Item 12 inteiro (diversões, lazer, entretenimento), exceto o subitem 12.13.
    var ITEM_12 = 'Domicílio do Tomador (Local do Show/Evento)';

    function localDeIncidencia(listLc) {
        if (!listLc) return REGRA_GERAL;

        var partes = String(listLc).trim().replace(/^0+/, '').split('.');
        var item = parseInt(partes[0], 10);
        var chave = item + '.' + (partes[1] || '00');

        if (Object.prototype.hasOwnProperty.call(EXCECOES, chave)) return EXCECOES[chave];
        if (item === 12 && chave !== '12.13') return ITEM_12;
        return REGRA_GERAL;
    }

    var api = { localDeIncidencia: localDeIncidencia, REGRA_GERAL: REGRA_GERAL };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else raiz.IncidenciaISS = api;
})(typeof window !== 'undefined' ? window : this);
