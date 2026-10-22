const botao = document.getElementById('mostrar-senha');

if (botao) {
    const senha = document.getElementById('senha');

    botao.addEventListener('click', function() {
        if (senha.type == 'password') {
            senha.type = 'text';
        } else {
            senha.type = 'password';
        }
    });
}

function somenteNumeros(campo) {
    let numeros = '';
    for (let caractere of campo.value) {
        if (caractere >= '0' && caractere <= '9' && numeros.length < 11) {
            numeros = numeros + caractere;
        }
    }
    campo.value = numeros;
}

const cpf = document.getElementById('cpf');
if (cpf) {
    somenteNumeros(cpf);
    cpf.addEventListener('input', function() {
        somenteNumeros(cpf);
    });
    cpf.addEventListener('paste', function(evento) {
        evento.preventDefault();
        cpf.value = evento.clipboardData.getData('text');
        somenteNumeros(cpf);
    });
}

const telefone = document.getElementById('telefone');
if (telefone) {
    somenteNumeros(telefone);
    telefone.addEventListener('input', function() {
        somenteNumeros(telefone);
    });
    telefone.addEventListener('paste', function(evento) {
        evento.preventDefault();
        telefone.value = evento.clipboardData.getData('text');
        somenteNumeros(telefone);
    });
}
