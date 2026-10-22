# Importações
# Ferramentas para aplicação, páginas, formulários, navegação, mensagens e sessão.
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
)

# Driver usado para conectar o Python ao Firebird.
import fdb

# Funções para gerar e conferir o hash das senhas.
from werkzeug.security import generate_password_hash, check_password_hash

# Compatibilidade com as senhas antigas salvas em Bcrypt.
from flask_bcrypt import Bcrypt

# Geração de relatórios em PDF, conforme o exemplo da professora.
from fpdf import FPDF


# Aplicação e banco de dados
app = Flask(__name__)
# Chave usada pelo Flask para assinar os dados da sessão.
app.config["SECRET_KEY"] = "chavesecreta"
bcrypt = Bcrypt(app)

# Execute na pasta do main.py ou informe o caminho completo do banco simplificado.
host = "localhost"
database = r"C:\Users\Aluno\Downloads\AutomaticFit-Recente\AutomaticFit\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"

# Abre a conexão usada pelas consultas e gravações do sistema.
con = fdb.connect(
    host=host, database=database, user=user, password=password, charset="UTF8"
)


# Datas e horários com validação manual
# O relógio vem do Firebird; os cálculos abaixo usam textos e números.
# Consulta a data e a hora do Firebird, sem importar uma biblioteca de datas.
def momento_atual():
    cursor = con.cursor()
    try:
        # CURRENT_DATE, EXTRACT e RDB$DATABASE aparecem na aula 08.
        # CURRENT_TIME fornece a hora atual para a mesma consulta.
        cursor.execute(
            """SELECT CURRENT_DATE,
                                 EXTRACT(HOUR FROM CURRENT_TIME),
                                 EXTRACT(MINUTE FROM CURRENT_TIME),
                                 EXTRACT(SECOND FROM CURRENT_TIME)
                          FROM RDB$DATABASE"""
        )
        agora = cursor.fetchone()
        hora = str(agora[1])
        minuto = str(agora[2])
        segundo = str(int(agora[3]))
        if len(hora) == 1:
            hora = "0" + hora
        if len(minuto) == 1:
            minuto = "0" + minuto
        if len(segundo) == 1:
            segundo = "0" + segundo
        return str(agora[0]) + " " + hora + ":" + minuto + ":" + segundo
    finally:
        cursor.close()


# Confere o formato da data e a quantidade de dias de cada mês.
def data_valida(valor):
    if not valor or len(valor) != 10:
        return False
    if valor[4] != "-" or valor[7] != "-":
        return False
    # Separa os números para conferir antes de converter para inteiro.
    numeros = valor[0:4] + valor[5:7] + valor[8:10]
    for caractere in numeros:
        if caractere not in "0123456789":
            return False
    ano = int(valor[0:4])
    mes = int(valor[5:7])
    dia = int(valor[8:10])
    if ano < 1 or mes < 1 or mes > 12:
        return False
    dias = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    # Ajusta fevereiro para 29 dias quando o ano é bissexto.
    if ano % 400 == 0 or (ano % 4 == 0 and ano % 100 != 0):
        dias[1] = 29
    if dia < 1 or dia > dias[mes - 1]:
        return False
    return True


# Aceita horários HH:MM ou HH:MM:SS dentro dos limites válidos.
def hora_valida(valor):
    if not valor or len(valor) not in (5, 8):
        return False
    if valor[2] != ":":
        return False
    numeros = valor[0:2] + valor[3:5]
    if len(valor) == 8:
        if valor[5] != ":":
            return False
        numeros = numeros + valor[6:8]
    for caractere in numeros:
        if caractere not in "0123456789":
            return False
    if int(valor[0:2]) > 23 or int(valor[3:5]) > 59:
        return False
    if len(valor) == 8 and int(valor[6:8]) > 59:
        return False
    return True


# Calcula a data máxima de nascimento para ter 18 anos completos.
def limite_nascimento():
    hoje = momento_atual()[0:10]
    ano = int(hoje[0:4]) - 18
    limite = str(ano) + hoje[4:10]
    if not data_valida(limite):
        limite = str(ano) + "-02-28"
    return limite


# Validação de senhas
# Exige tamanho válido, maiúscula, minúscula, número e símbolo.
def validar_senha(senha):
    min_caractere = False
    min_upper = False
    min_lower = False
    min_num = False
    min_caractere_esp = False

    if 8 <= len(senha) <= 128:
        min_caractere = True

    # Percorre a senha e marca quais exigências já foram atendidas.
    for caractere in senha:
        if caractere.isalpha() and caractere == caractere.upper():
            min_upper = True
        if caractere.isalpha() and caractere == caractere.lower():
            min_lower = True
        if caractere.isdigit():
            min_num = True
        if (
            not caractere.isalpha()
            and not caractere.isdigit()
            and not caractere.isspace()
        ):
            min_caractere_esp = True

    if min_caractere and min_upper and min_lower and min_num and min_caractere_esp:
        return True
    else:
        return False


# Mantém o acesso às contas antigas que usam Bcrypt.
# Compara a senha digitada com o hash antigo ou atual.
def conferir_senha(hash_salvo, senha):
    if not hash_salvo:
        return False
    try:
        if hash_salvo[:2] == "$2":
            return bcrypt.check_password_hash(hash_salvo, senha)
        else:
            return check_password_hash(hash_salvo, senha)
    except Exception:
        return False


# Confere a força e impede repetir a senha atual e as três anteriores.
def verificar_nova_senha(id_usuario, senha):
    if not validar_senha(senha):
        return "Use de 8 a 128 caracteres, maiúscula, minúscula, número e símbolo."

    if id_usuario is not None:
        cursor = con.cursor()
        try:
            cursor.execute(
                """SELECT SENHA
                              FROM USUARIOS
                              WHERE ID_USUARIO = ?""",
                (id_usuario,),
            )
            atual = cursor.fetchone()
            if atual and conferir_senha(atual[0], senha):
                return "A nova senha não pode ser igual à senha atual."

            cursor.execute(
                """SELECT SENHA
                              FROM HISTORICO_SENHAS
                              WHERE ID_USUARIO = ?
                              ORDER BY ID_HISTORICO DESC""",
                (id_usuario,),
            )
            # Confere primeiro os três hashes antigos mais recentes.
            historico = cursor.fetchall()
            quantidade = 0
            for registro in historico:
                if quantidade < 3:
                    if conferir_senha(registro[0], senha):
                        return "Você não pode reutilizar as três últimas senhas."
                    quantidade = quantidade + 1
            return ""
        finally:
            cursor.close()
    return ""


# Usuário autenticado e dados pessoais
# Busca a conta da sessão e recusa usuário inativo, bloqueado ou com perfil inválido.
def buscar_usuario():
    # Sem ID na sessão, não há uma conta autenticada para consultar.
    if "id_usuario" not in session:
        return None

    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO_USUARIO, TELEFONE, CPF,
                              DATA_NASCIMENTO, TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
                          FROM USUARIOS
                          WHERE ID_USUARIO = ?""",
            (session["id_usuario"],),
        )
        usuario = cursor.fetchone()
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        cursor.close()

    if not usuario or usuario[10] != 1 or usuario[9] == 1:
        session.clear()
        flash("Faça login com uma conta ativa e liberada.", "erro")
        return None
    if usuario[4] not in ("ALUNO", "PERSONAL", "ADMINISTRADOR"):
        session.clear()
        return None
    return usuario


# Retira espaços, parênteses e hífen do telefone.
def limpar_telefone(telefone):
    return (
        telefone.replace("(", "")
        .replace(")", "")
        .replace("-", "")
        .replace(" ", "")
        .strip()
    )


# Confere tamanho e formato básico do e-mail.
def validar_email(email):
    if not email or len(email) > 100 or email.count("@") != 1:
        return False
    for caractere in email:
        if caractere.isspace():
            return False
    partes = email.split("@")
    if not partes[0] or not partes[1] or "." not in partes[1]:
        return False
    if partes[1][0] == "." or partes[1][-1] == "." or ".." in email:
        return False
    return True


# Calcula os dois dígitos verificadores do CPF.
# Confere os 11 números e calcula os dois dígitos verificadores do CPF.
def validar_cpf(cpf):
    if len(cpf) != 11:
        return False
    for caractere in cpf:
        if caractere not in "0123456789":
            return False
    if cpf == cpf[0] * 11:
        return False
    # Faz uma rodada para o primeiro dígito verificador e outra para o segundo.
    for tamanho in (9, 10):
        soma = 0
        peso = tamanho + 1
        for posicao in range(tamanho):
            soma = soma + int(cpf[posicao]) * peso
            peso = peso - 1
        digito = (soma * 10) % 11
        if digito == 10:
            digito = 0
        if digito != int(cpf[tamanho]):
            return False
    return True


# Recusa datas inválidas, futuras e pessoas com menos de 18 anos.
def validar_nascimento(nascimento):
    if not nascimento:
        return "Informe a data de nascimento. A idade mínima é 18 anos."
    if not data_valida(nascimento):
        return "Informe uma data de nascimento válida."
    hoje = momento_atual()[0:10]
    if nascimento > hoje:
        return "A data de nascimento não pode ser futura."
    idade = int(hoje[0:4]) - int(nascimento[0:4])
    # Desconta um ano se o aniversário ainda não aconteceu neste ano.
    if hoje[5:10] < nascimento[5:10]:
        idade = idade - 1
    if idade < 18:
        return "É necessário ter pelo menos 18 anos completos para se cadastrar."
    return ""


# Reúne as validações dos dados pessoais antes de salvar.
def validar_pessoa(nome, email, telefone, cpf, nascimento):
    if not nome or len(nome) > 254:
        return "Informe um nome com até 254 caracteres."
    if not validar_email(email):
        return "Informe um e-mail válido com até 100 caracteres."
    # O telefone é opcional; se preenchido, precisa passar pelas verificações.
    if telefone:
        if len(telefone) not in (10, 11):
            return "Informe telefone com DDD: 10 ou 11 números, sem o código +55."
        for caractere in telefone:
            if caractere not in "0123456789":
                return "O telefone deve conter somente números."
        if telefone[0] == "0" or telefone == telefone[0] * len(telefone):
            return "Informe um telefone com DDD válido, sem o zero da operadora."
        if len(telefone) == 11 and telefone[2] != "9":
            return "O celular deve ter DDD e nove números, começando com 9."
        if len(telefone) == 10 and telefone[2] not in "2345":
            return "Informe um telefone fixo com DDD ou um celular com 11 números."
    if cpf and not validar_cpf(cpf):
        return "Informe um CPF válido com exatamente 11 números."
    return validar_nascimento(nascimento)


# Procura o mesmo e-mail em outra conta, sem contar o próprio usuário em edição.
def email_repetido(email, id_usuario):
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_USUARIO, EMAIL
                          FROM USUARIOS"""
        )
        usuarios = cursor.fetchall()
        for usuario in usuarios:
            if usuario[0] != id_usuario and usuario[1].strip().lower() == email:
                return True
        return False
    finally:
        cursor.close()


# Consultas das aulas
# Converte a data de AAAA-MM-DD para DD/MM/AAAA somente para exibição.
def formatar_data(valor):
    if not valor:
        return "Não informado"
    texto = str(valor)
    return texto[8:10] + "/" + texto[5:7] + "/" + texto[0:4]


# Monta as aulas com nomes, inscritos, datas formatadas e situação dos horários.
def buscar_aulas():
    agora = momento_atual()
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_AULA, NOME, ID_MODALIDADE, ID_PROFESSOR, DATA_AULA, HORA_INICIO,
                              HORA_FIM, CAPACIDADE, LOCAL_AULA, SITUACAO
                          FROM AULAS
                          ORDER BY DATA_AULA, HORA_INICIO"""
        )
        registros = cursor.fetchall()
        aulas = []
        for registro in registros:
            aula = list(registro)
            cursor.execute(
                """SELECT NOME, ATIVA
                              FROM MODALIDADES
                              WHERE ID_MODALIDADE = ?""",
                (aula[2],),
            )
            modalidade = cursor.fetchone()
            cursor.execute(
                """SELECT NOME
                              FROM USUARIOS
                              WHERE ID_USUARIO = ?""",
                (aula[3],),
            )
            professor = cursor.fetchone()
            cursor.execute(
                """SELECT ID_INSCRICAO
                              FROM INSCRICOES
                              WHERE ID_AULA = ? AND ATIVA = 1""",
                (aula[0],),
            )
            inscritos = cursor.fetchall()
            # Acrescenta à lista os dados usados pelos cartões e botões das telas.
            aula.append(modalidade[0])
            aula.append(professor[0])
            aula.append(len(inscritos))
            aula.append(modalidade[1])
            aula.append(formatar_data(aula[4]))
            aula.append(str(aula[5])[0:5])
            aula.append(str(aula[6])[0:5])
            aula.append(str(aula[4]) + " " + str(aula[5])[0:8] > agora)
            aula.append(str(aula[4]) + " " + str(aula[6])[0:8] <= agora)
            aulas.append(aula)
        return aulas
    finally:
        cursor.close()


# Procura uma aula pelo ID na lista preparada.
def buscar_aula(id_aula):
    aulas = buscar_aulas()
    for aula in aulas:
        if aula[0] == id_aula:
            return aula
    return None


# Lista as inscrições ativas da aula e acrescenta o nome de cada aluno.
def buscar_inscritos(id_aula):
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_INSCRICAO, ID_AULA, ID_USUARIO, ATIVA, PRESENTE
                          FROM INSCRICOES
                          WHERE ID_AULA = ? AND ATIVA = 1
                          ORDER BY ID_INSCRICAO""",
            (id_aula,),
        )
        registros = cursor.fetchall()
        inscritos = []
        for registro in registros:
            inscricao = list(registro)
            cursor.execute(
                """SELECT NOME
                              FROM USUARIOS
                              WHERE ID_USUARIO = ?""",
                (inscricao[2],),
            )
            pessoa = cursor.fetchone()
            inscricao.append(pessoa[0])
            inscritos.append(inscricao)
        return inscritos
    finally:
        cursor.close()


# Página inicial e cadastro
# Exibe a página inicial pública.
@app.route("/")
def index():
    return render_template("landing.html")


# Valida o formulário e cadastra uma conta de aluno com senha em hash.
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        # Lê e limpa os dados enviados pelo formulário.
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        telefone = limpar_telefone(request.form.get("telefone", ""))
        cpf = request.form.get("cpf", "").replace(".", "").replace("-", "").strip()
        nascimento = request.form.get("data_nascimento", "")
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar_senha", "")
        # Confere os dados, os campos obrigatórios e a confirmação da senha.
        erro = validar_pessoa(nome, email, telefone, cpf, nascimento)
        if not cpf or not nascimento:
            erro = "Preencha CPF e data de nascimento."
        if senha != confirmar:
            erro = "As senhas não coincidem."
        if not erro:
            erro = verificar_nova_senha(None, senha)
        if erro:
            flash(erro, "erro")
            return render_template(
                "cadastro.html", nascimento_maximo=limite_nascimento()
            )

        cursor = con.cursor()
        try:
            if email_repetido(email, None):
                con.rollback()
                flash("Este e-mail já está cadastrado.", "erro")
                return render_template(
                    "cadastro.html", nascimento_maximo=limite_nascimento()
                )
            # Gera o hash; a senha digitada não é gravada como texto puro.
            hash_senha = generate_password_hash(senha)
            cursor.execute(
                """INSERT INTO USUARIOS (NOME, EMAIL, TELEFONE, CPF, DATA_NASCIMENTO,
                                  SENHA, TIPO_USUARIO, ATIVO, BLOQUEADO, TENTATIVAS_LOGIN)
                              VALUES (?, ?, ?, ?, ?, ?, 'ALUNO', 1, 0, 0)""",
                (nome, email, telefone, cpf, nascimento, hash_senha),
            )
            con.commit()
            flash("Cadastro realizado com sucesso! Faça seu login.", "sucesso")
            return redirect(url_for("login"))
        except Exception as e:
            con.rollback()
            print(e)
            flash("Não foi possível cadastrar. Confira os dados informados.", "erro")
        finally:
            cursor.close()
    return render_template("cadastro.html", nascimento_maximo=limite_nascimento())


# Login e bloqueio
# Confere a conta e a senha; bloqueia após três tentativas incorretas.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        if not validar_email(email) or not senha or len(senha) > 128:
            flash("Preencha um e-mail válido e a senha (até 128 caracteres).", "erro")
            return render_template("login.html")
        cursor = con.cursor()
        try:
            cursor.execute(
                """SELECT ID_USUARIO, EMAIL, SENHA, ATIVO, BLOQUEADO, TENTATIVAS_LOGIN
                              FROM USUARIOS"""
            )
            # Procura a conta pelo e-mail normalizado.
            usuarios = cursor.fetchall()
            usuario = None
            for pessoa in usuarios:
                if pessoa[1].strip().lower() == email:
                    usuario = pessoa

            # Recusa conta inexistente, inativa ou bloqueada antes de conferir a senha.
            if not usuario:
                flash("E-mail ou senha incorretos.", "erro")
            elif usuario[3] != 1:
                flash("Usuário inativo.", "erro")
            elif usuario[4] == 1:
                flash("Usuário bloqueado. Procure o administrador.", "erro")
            elif conferir_senha(usuario[2], senha):
                # No login correto, zera o contador de erros da conta.
                cursor.execute(
                    """UPDATE USUARIOS
                                  SET TENTATIVAS_LOGIN = 0
                                  WHERE ID_USUARIO = ?""",
                    (usuario[0],),
                )
                con.commit()
                session.clear()
                # Guarda o ID para reconhecer a conta nas próximas páginas.
                session["id_usuario"] = usuario[0]
                return redirect(url_for("voltar_home"))
            else:
                # Na senha errada, soma uma tentativa e decide se deve bloquear.
                tentativas = usuario[5]
                if tentativas is None:
                    tentativas = 0
                tentativas = tentativas + 1
                bloqueado = 0
                if tentativas >= 3:
                    bloqueado = 1
                    flash("Usuário bloqueado após três tentativas incorretas.", "erro")
                else:
                    flash(
                        f"E-mail ou senha incorretos. Tentativa {tentativas} de 3.",
                        "erro",
                    )
                # Salva o contador e a marca de bloqueio somente nesta conta.
                cursor.execute(
                    """UPDATE USUARIOS
                                  SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                                  WHERE ID_USUARIO = ?""",
                    (tentativas, bloqueado, usuario[0]),
                )
            con.commit()
        except Exception as e:
            con.rollback()
            print(e)
            flash("Não foi possível concluir o login. Confira o terminal.", "erro")
        finally:
            cursor.close()
    return render_template("login.html")


# Encerra a sessão da conta conectada e volta para o login.
@app.route("/logout", methods=["POST"])
def logout():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    session.clear()
    flash("Você saiu da sua conta.", "sucesso")
    return redirect(url_for("login"))


# Início dos perfis
# Encaminha o usuário para o início correspondente ao seu perfil.
@app.route("/minha-home")
def voltar_home():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] == "ADMINISTRADOR":
        return redirect(url_for("administrador"))
    elif usuario[4] == "PERSONAL":
        return redirect(url_for("personal"))
    else:
        return redirect(url_for("aluno"))


# Exibe os totais e as próximas aulas para o administrador.
@app.route("/administrador")
def administrador():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    hoje = momento_atual()[0:10]
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_USUARIO
                          FROM USUARIOS
                          WHERE TIPO_USUARIO = 'ALUNO'"""
        )
        total_alunos = len(cursor.fetchall())
        cursor.execute(
            """SELECT ID_USUARIO
                          FROM USUARIOS
                          WHERE TIPO_USUARIO = 'PERSONAL'"""
        )
        total_professores = len(cursor.fetchall())
        cursor.execute(
            """SELECT ID_MODALIDADE
                          FROM MODALIDADES"""
        )
        total_modalidades = len(cursor.fetchall())
        aulas = []
        aulas_hoje = 0
        for aula in buscar_aulas():
            if aula[9] == "AGENDADA" and aula[17]:
                aulas.append(aula)
            if aula[9] == "AGENDADA" and str(aula[4]) == hoje:
                aulas_hoje = aulas_hoje + 1
        con.commit()
    finally:
        cursor.close()
    return render_template(
        "dashboard.html",
        usuario=usuario,
        total_alunos=total_alunos,
        total_professores=total_professores,
        modalidades=total_modalidades,
        aulas=aulas,
        total_aulas=len(aulas),
        aulas_hoje=aulas_hoje,
    )


# Mostra ao aluno as aulas futuras de modalidades ativas.
@app.route("/aluno")
def aluno():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ALUNO":
        return redirect(url_for("voltar_home"))
    aulas = []
    for aula in buscar_aulas():
        if aula[9] == "AGENDADA" and aula[13] == 1 and aula[17]:
            aulas.append(aula)
    con.commit()
    return render_template("grade.html", usuario=usuario, aulas=aulas)


# Exibe o resumo das aulas e dos inscritos do professor conectado.
@app.route("/personal")
def personal():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "PERSONAL":
        return redirect(url_for("voltar_home"))
    hoje = momento_atual()[0:10]
    aulas = []
    agendadas = 0
    aulas_hoje = 0
    total_inscritos = 0
    for aula in buscar_aulas():
        if aula[3] == usuario[0]:
            aulas.append(aula)
            if str(aula[4]) == hoje and aula[9] == "AGENDADA":
                aulas_hoje = aulas_hoje + 1
            total_inscritos = total_inscritos + aula[12]
            if aula[9] == "AGENDADA":
                agendadas = agendadas + 1
    con.commit()
    return render_template(
        "personal.html",
        usuario=usuario,
        aulas=aulas,
        total_aulas=len(aulas),
        total_agendadas=agendadas,
        aulas_hoje=aulas_hoje,
        total_inscritos=total_inscritos,
    )


# Mostra a agenda de aulas do próprio professor.
@app.route("/agenda")
def agenda():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "PERSONAL":
        return redirect(url_for("voltar_home"))
    aulas = []
    for aula in buscar_aulas():
        if aula[3] == usuario[0]:
            aulas.append(aula)
    con.commit()
    return render_template(
        "aulas.html", usuario=usuario, aulas=aulas, titulo="Minha Agenda e Aulas"
    )


# Reaproveita a função de agenda para abrir a página de presenças.
@app.route("/presencas")
def presencas():
    return agenda()


# Perfil e edição dos dados
# Mostra os dados da conta conectada.
@app.route("/perfil")
def perfil():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    return render_template(
        "perfil.html",
        usuario=usuario,
        titulo="Meu Perfil",
        nascimento_formatado=formatar_data(usuario[7]),
    )


# Valida e atualiza os dados do próprio usuário, mantendo seu ID.
@app.route("/editar-dados", methods=["GET", "POST"])
def editar_dados():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        telefone = limpar_telefone(request.form.get("telefone", ""))
        cpf = request.form.get("cpf", "").replace(".", "").replace("-", "").strip()
        nascimento = request.form.get("data_nascimento", "")
        if not nascimento:
            nascimento = None
        erro = validar_pessoa(nome, email, telefone, cpf, nascimento)
        cursor = con.cursor()
        try:
            if not erro and email_repetido(email, usuario[0]):
                erro = "Este e-mail já está cadastrado."
            if erro:
                con.rollback()
                flash(erro, "erro")
            else:
                cursor.execute(
                    """UPDATE USUARIOS
                                  SET NOME = ?, EMAIL = ?, TELEFONE = ?, CPF = ?,
                                      DATA_NASCIMENTO = ?
                                  WHERE ID_USUARIO = ?""",
                    (nome, email, telefone, cpf, nascimento, usuario[0]),
                )
                con.commit()
                flash("Dados atualizados com sucesso!", "sucesso")
                return redirect(url_for("perfil"))
        except Exception as e:
            con.rollback()
            print(e)
            flash("Não foi possível salvar. Confira os dados.", "erro")
        finally:
            cursor.close()
    return render_template(
        "usuario_form.html",
        usuario=usuario,
        pessoa=usuario,
        proprio=True,
        editando=True,
        titulo="Editar meus dados",
        nascimento_maximo=limite_nascimento(),
    )


# Alteração de senha
# Confere a senha atual, guarda o hash antigo e salva a nova senha.
@app.route("/alterar-senha", methods=["GET", "POST"])
def alterar_senha():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if request.method == "POST":
        atual = request.form.get("senha_atual", "")
        nova = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar", "")
        erro = ""
        cursor = con.cursor()
        try:
            # Confere a senha atual, a confirmação e as regras da nova senha.
            if not conferir_senha(usuario[3], atual):
                erro = "A senha atual está incorreta."
            elif nova != confirmar:
                erro = "As novas senhas não coincidem."
            else:
                erro = verificar_nova_senha(usuario[0], nova)
            if erro:
                con.rollback()
                flash(erro, "erro")
            else:
                hash_senha = generate_password_hash(nova)
                # Guarda o hash anterior para impedir sua reutilização.
                cursor.execute(
                    """INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                                  VALUES (?, ?)""",
                    (usuario[0], usuario[3]),
                )
                cursor.execute(
                    """UPDATE USUARIOS
                                  SET SENHA = ?
                                  WHERE ID_USUARIO = ?""",
                    (hash_senha, usuario[0]),
                )
                con.commit()
                flash("Senha alterada com sucesso!", "sucesso")
                return redirect(url_for("perfil"))
        except Exception as e:
            con.rollback()
            print(e)
            flash("Não foi possível alterar a senha.", "erro")
        finally:
            cursor.close()
    return render_template("alterar_senha.html", usuario=usuario)


# Usuários
# Lista as contas por perfil, com acesso exclusivo do administrador.
@app.route("/usuarios")
def usuarios():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    filtro = request.args.get("perfil", "ALUNO")
    if filtro not in ("ALUNO", "PERSONAL", "ADMINISTRADOR"):
        return redirect(url_for("usuarios"))
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO_USUARIO, TELEFONE, CPF,
                              DATA_NASCIMENTO, TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
                          FROM USUARIOS
                          WHERE TIPO_USUARIO = ?
                          ORDER BY NOME""",
            (filtro,),
        )
        pessoas = cursor.fetchall()
        con.commit()
    finally:
        cursor.close()
    titulo = "Alunos"
    if filtro == "PERSONAL":
        titulo = "Professores"
    elif filtro == "ADMINISTRADOR":
        titulo = "Administradores"
    return render_template(
        "usuarios.html", usuario=usuario, pessoas=pessoas, filtro=filtro, titulo=titulo
    )


# Permite ao administrador cadastrar e editar contas e seu bloqueio.
@app.route("/usuarios/novo", methods=["GET", "POST"])
@app.route("/usuarios/<int:id_usuario>/editar", methods=["GET", "POST"])
def usuario_form(id_usuario=None):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    pessoa = ["", "", "", "", request.args.get("perfil", "ALUNO"), "", "", "", 0, 0, 1]
    titulo = "Cadastrar usuário"
    editando = False
    cursor = con.cursor()
    try:
        # Se recebeu um ID, carrega a conta existente para edição.
        if id_usuario is not None:
            editando = True
            titulo = "Editar usuário"
            cursor.execute(
                """SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO_USUARIO, TELEFONE, CPF,
                                  DATA_NASCIMENTO, TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
                              FROM USUARIOS
                              WHERE ID_USUARIO = ?""",
                (id_usuario,),
            )
            pessoa = cursor.fetchone()
            if not pessoa:
                con.rollback()
                flash("Usuário não encontrado.", "erro")
                return redirect(url_for("usuarios"))

        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            email = request.form.get("email", "").strip().lower()
            telefone = limpar_telefone(request.form.get("telefone", ""))
            cpf = request.form.get("cpf", "").replace(".", "").replace("-", "").strip()
            nascimento = request.form.get("data_nascimento", "")
            if not nascimento:
                nascimento = None
            tipo = request.form.get("tipo_usuario", "ALUNO")
            ativo = int(request.form.get("ativo", "1"))
            bloqueado = int(request.form.get("bloqueado", "0"))
            tentativas = int(request.form.get("tentativas_login", "0"))
            senha = request.form.get("senha", "")
            erro = validar_pessoa(nome, email, telefone, cpf, nascimento)
            if tipo not in ("ALUNO", "PERSONAL", "ADMINISTRADOR"):
                erro = "Perfil inválido."
            if (
                ativo not in (0, 1)
                or bloqueado not in (0, 1)
                or not 0 <= tentativas <= 2147483647
            ):
                erro = "Confira a situação, o bloqueio e as tentativas."
            if not erro and email_repetido(email, id_usuario):
                erro = "Este e-mail já está cadastrado."
            if not erro and (senha or not editando):
                erro = verificar_nova_senha(id_usuario, senha)
            if erro:
                con.rollback()
                flash(erro, "erro")
            else:
                if editando:
                    hash_senha = pessoa[3]
                    # Na edição, só troca o hash quando uma nova senha foi preenchida.
                    if senha:
                        hash_senha = generate_password_hash(senha)
                        cursor.execute(
                            """INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                                          VALUES (?, ?)""",
                            (id_usuario, pessoa[3]),
                        )
                    cursor.execute(
                        """UPDATE USUARIOS
                                      SET NOME = ?, EMAIL = ?, TELEFONE = ?, CPF = ?,
                                          DATA_NASCIMENTO = ?, TIPO_USUARIO = ?, ATIVO = ?,
                                          BLOQUEADO = ?, TENTATIVAS_LOGIN = ?, SENHA = ?
                                      WHERE ID_USUARIO = ?""",
                        (
                            nome,
                            email,
                            telefone,
                            cpf,
                            nascimento,
                            tipo,
                            ativo,
                            bloqueado,
                            tentativas,
                            hash_senha,
                            id_usuario,
                        ),
                    )
                else:
                    hash_senha = generate_password_hash(senha)
                    cursor.execute(
                        """INSERT INTO USUARIOS (NOME, EMAIL, TELEFONE, CPF,
                                          DATA_NASCIMENTO, TIPO_USUARIO, ATIVO, BLOQUEADO,
                                          TENTATIVAS_LOGIN, SENHA)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            nome,
                            email,
                            telefone,
                            cpf,
                            nascimento,
                            tipo,
                            ativo,
                            bloqueado,
                            tentativas,
                            hash_senha,
                        ),
                    )
                con.commit()
                flash("Usuário salvo com sucesso!", "sucesso")
                return redirect(url_for("usuarios", perfil=tipo))
        else:
            con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash("Não foi possível salvar o usuário. Confira os dados.", "erro")
    finally:
        cursor.close()
    return render_template(
        "usuario_form.html",
        usuario=usuario,
        pessoa=pessoa,
        proprio=False,
        editando=editando,
        titulo=titulo,
        nascimento_maximo=limite_nascimento(),
    )


# Cadastro e edição de modalidades
# Lista modalidades e a quantidade de aulas vinculadas a cada uma.
@app.route("/modalidades")
def modalidades():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_MODALIDADE, NOME, DESCRICAO, DURACAO, ATIVA
                          FROM MODALIDADES
                          ORDER BY NOME"""
        )
        registros = cursor.fetchall()
        lista = []
        for registro in registros:
            item = list(registro)
            cursor.execute(
                """SELECT ID_AULA
                              FROM AULAS
                              WHERE ID_MODALIDADE = ?""",
                (item[0],),
            )
            item.append(len(cursor.fetchall()))
            lista.append(item)
        con.commit()
    finally:
        cursor.close()
    return render_template("modalidades.html", usuario=usuario, modalidades=lista)


# Cadastra ou edita modalidades, impedindo nomes duplicados.
@app.route("/modalidades/nova", methods=["GET", "POST"])
@app.route("/modalidades/<int:id_modalidade>/editar", methods=["GET", "POST"])
def modalidade_form(id_modalidade=None):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    item = ["", "", "", 50, 1]
    editando = False
    titulo = "Nova modalidade"
    cursor = con.cursor()
    try:
        if id_modalidade is not None:
            editando = True
            titulo = "Editar modalidade"
            cursor.execute(
                """SELECT ID_MODALIDADE, NOME, DESCRICAO, DURACAO, ATIVA
                              FROM MODALIDADES
                              WHERE ID_MODALIDADE = ?""",
                (id_modalidade,),
            )
            item = cursor.fetchone()
            if not item:
                con.rollback()
                flash("Modalidade não encontrada.", "erro")
                return redirect(url_for("modalidades"))

        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            descricao = request.form.get("descricao", "").strip()
            duracao = int(request.form.get("duracao", "0"))
            ativa = int(request.form.get("ativa", "1"))
            erro = ""
            if not nome or len(nome) > 100 or not descricao or len(descricao) > 500:
                erro = "Preencha nome e descrição dentro dos limites indicados."
            if not 1 <= duracao <= 1440 or ativa not in (0, 1):
                erro = "Duração ou situação inválida."
            cursor.execute(
                """SELECT ID_MODALIDADE, NOME
                              FROM MODALIDADES"""
            )
            registros = cursor.fetchall()
            # Compara nomes sem espaços externos e sem diferença entre maiúsculas e minúsculas.
            for registro in registros:
                if (
                    registro[0] != id_modalidade
                    and registro[1].strip().lower() == nome.lower()
                ):
                    erro = "Modalidade já existe."
            if erro:
                con.rollback()
                flash(erro, "erro")
            else:
                if editando:
                    cursor.execute(
                        """UPDATE MODALIDADES
                                      SET NOME = ?, DESCRICAO = ?, DURACAO = ?, ATIVA = ?
                                      WHERE ID_MODALIDADE = ?""",
                        (nome, descricao, duracao, ativa, id_modalidade),
                    )
                else:
                    cursor.execute(
                        """INSERT INTO MODALIDADES (NOME, DESCRICAO, DURACAO, ATIVA)
                                      VALUES (?, ?, ?, ?)""",
                        (nome, descricao, duracao, ativa),
                    )
                con.commit()
                flash("Modalidade salva com sucesso!", "sucesso")
                return redirect(url_for("modalidades"))
        else:
            con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash("Não foi possível salvar a modalidade. Confira os dados.", "erro")
    finally:
        cursor.close()
    return render_template(
        "modalidade_form.html",
        usuario=usuario,
        item=item,
        editando=editando,
        titulo=titulo,
    )


# Exclusão de modalidade
# Exclui a modalidade somente se ela não tiver aulas vinculadas.
@app.route("/modalidades/<int:id_modalidade>/excluir", methods=["GET", "POST"])
def modalidade_excluir(id_modalidade):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT NOME
                          FROM MODALIDADES
                          WHERE ID_MODALIDADE = ?""",
            (id_modalidade,),
        )
        item = cursor.fetchone()
        if not item:
            con.rollback()
            flash("Modalidade não encontrada.", "erro")
            return redirect(url_for("modalidades"))
        if request.method == "POST":
            # Antes de excluir, verifica se alguma aula utiliza esta modalidade.
            cursor.execute(
                """SELECT ID_AULA
                              FROM AULAS
                              WHERE ID_MODALIDADE = ?""",
                (id_modalidade,),
            )
            if cursor.fetchone():
                con.rollback()
                flash(
                    "Não é possível excluir: a modalidade possui aulas vinculadas.",
                    "erro",
                )
                return redirect(url_for("modalidades"))
            cursor.execute(
                """DELETE
                              FROM MODALIDADES
                              WHERE ID_MODALIDADE = ?""",
                (id_modalidade,),
            )
            con.commit()
            flash("Modalidade excluída com sucesso!", "sucesso")
            return redirect(url_for("modalidades"))
        con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash("Não foi possível excluir a modalidade.", "erro")
        return redirect(url_for("modalidades"))
    finally:
        cursor.close()
    return render_template(
        "confirmar.html",
        usuario=usuario,
        titulo="Excluir modalidade",
        mensagem=f"Excluir a modalidade {item[0]}?",
        voltar=url_for("modalidades"),
        botao="Excluir modalidade",
    )


# Listagem e validação das aulas
# Exibe a listagem de aulas para o administrador.
@app.route("/aulas")
def aulas():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    lista = buscar_aulas()
    con.commit()
    return render_template("aulas.html", usuario=usuario, aulas=lista, titulo="Aulas")


# Gera o relatório de aulas para o administrador baixar.
@app.route("/aulas/relatorio", methods=["GET"])
def relatorio_aulas():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))

    lista = buscar_aulas()
    con.commit()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(0, 10, "Relatório de Aulas - Automatic Fit", ln=True, align="C")
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font("Arial", size=12)

    if not lista:
        pdf.cell(0, 10, "Nenhuma aula cadastrada.", ln=True)
    for aula in lista:
        texto = f"ID: {aula[0]} - {aula[1]}\n"
        texto += f"Modalidade: {aula[10]} | Professor: {aula[11]}\n"
        texto += f"Data: {aula[14]} | Horário: {aula[15]} às {aula[16]}\n"
        texto += f"Local: {aula[8]} | Inscritos: {aula[12]}/{aula[7]}\n"
        texto += f"Situação: {aula[9]}"
        # A fonte Arial do exemplo aceita caracteres latinos; troca os demais por ?.
        texto = texto.encode("latin-1", errors="replace").decode("latin-1")
        pdf.multi_cell(0, 7, texto)
        pdf.ln(5)

    pdf.ln(5)
    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(0, 10, f"Total de aulas cadastradas: {len(lista)}", ln=True, align="C")
    pdf_path = app.root_path + "/relatorio_aulas_" + str(usuario[0]) + ".pdf"
    pdf.output(pdf_path)
    return send_file(
        pdf_path,
        as_attachment=True,
        mimetype="application/pdf",
        download_name="relatorio_aulas.pdf",
        max_age=0,
    )


# Confere dados, professor, modalidade, capacidade e conflitos de horário.
def validar_aula(
    id_aula, nome, modalidade, professor, dia, inicio, fim, capacidade, local
):
    if not nome or len(nome) > 100 or not local or len(local) > 100:
        return "Informe nome da aula e local com até 100 caracteres."
    if not 1 <= capacidade <= 2147483647:
        return "Capacidade inválida. Informe um número maior que zero."
    # Valida as datas e os horários antes de compará-los.
    if not data_valida(dia) or not hora_valida(inicio) or not hora_valida(fim):
        return "Preencha uma data e horários válidos."
    if len(inicio) == 5:
        inicio = inicio + ":00"
    if len(fim) == 5:
        fim = fim + ":00"
    if fim <= inicio:
        return "O horário de término deve ser maior que o horário de início."
    if dia + " " + inicio <= momento_atual():
        return "A aula precisa começar em uma data e horário futuros."
    cursor = con.cursor()
    try:
        # Exige modalidade cadastrada e ativa.
        cursor.execute(
            """SELECT ATIVA
                          FROM MODALIDADES
                          WHERE ID_MODALIDADE = ?""",
            (modalidade,),
        )
        modo = cursor.fetchone()
        if not modo or modo[0] != 1:
            return "Selecione uma modalidade cadastrada e ativa."
        # Exige professor ativo, não bloqueado e com perfil PERSONAL.
        cursor.execute(
            """SELECT TIPO_USUARIO, ATIVO, BLOQUEADO
                          FROM USUARIOS
                          WHERE ID_USUARIO = ?""",
            (professor,),
        )
        pessoa = cursor.fetchone()
        if not pessoa or pessoa[0] != "PERSONAL" or pessoa[1] != 1 or pessoa[2] == 1:
            return "Instrutor não permitido. Selecione um Professor ativo."
        cursor.execute(
            """SELECT ID_AULA, HORA_INICIO, HORA_FIM, SITUACAO, ID_MODALIDADE
                          FROM AULAS
                          WHERE ID_PROFESSOR = ? AND DATA_AULA = ?""",
            (professor, dia),
        )
        registros = cursor.fetchall()
        # Recusa repetição e sobreposição de horários do mesmo professor.
        for registro in registros:
            if (
                registro[0] != id_aula
                and registro[4] == modalidade
                and str(registro[1])[0:8] == inicio
            ):
                return "Já existe uma aula dessa modalidade com esse professor, dia e horário."
            if registro[0] != id_aula and registro[3] == "AGENDADA":
                if inicio < str(registro[2])[0:8] and fim > str(registro[1])[0:8]:
                    return "O professor já possui aula nesse dia e horário."
        if id_aula is not None:
            cursor.execute(
                """SELECT ID_INSCRICAO
                              FROM INSCRICOES
                              WHERE ID_AULA = ? AND ATIVA = 1""",
                (id_aula,),
            )
            # A edição não pode reduzir as vagas abaixo da quantidade de inscritos.
            if capacidade < len(cursor.fetchall()):
                return "A capacidade não pode ser menor que o número de inscritos."
        return ""
    finally:
        cursor.close()


# Cadastro e edição de aulas
# Carrega o formulário e salva o cadastro ou a edição da aula.
@app.route("/aulas/nova", methods=["GET", "POST"])
@app.route("/aulas/<int:id_aula>/editar", methods=["GET", "POST"])
def aula_form(id_aula=None):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    item = ["", "", "", "", "", "", "", "", "", "AGENDADA"]
    editando = False
    titulo = "Criar aula"
    modos = []
    professores = []
    modalidade_selecionada = 0
    professor_selecionado = 0
    cursor = con.cursor()
    try:
        if id_aula is not None:
            editando = True
            titulo = "Editar aula"
            item = buscar_aula(id_aula)
            if not item:
                con.rollback()
                flash("Aula não encontrada.", "erro")
                return redirect(url_for("aulas"))
            modalidade_selecionada = item[2]
            professor_selecionado = item[3]
        cursor.execute(
            """SELECT ID_MODALIDADE, NOME
                          FROM MODALIDADES
                          WHERE ATIVA = 1
                          ORDER BY NOME"""
        )
        modos = cursor.fetchall()
        cursor.execute(
            """SELECT ID_USUARIO, NOME
                          FROM USUARIOS
                          WHERE TIPO_USUARIO = 'PERSONAL' AND ATIVO = 1 AND BLOQUEADO = 0
                          ORDER BY NOME"""
        )
        professores = cursor.fetchall()
        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            modalidade = int(request.form.get("id_modalidade", "0"))
            professor = int(request.form.get("id_professor", "0"))
            modalidade_selecionada = modalidade
            professor_selecionado = professor
            dia = request.form.get("data_aula", "")
            inicio = request.form.get("hora_inicio", "")
            fim = request.form.get("hora_fim", "")
            # Completa os segundos para salvar os horários no mesmo formato.
            if len(inicio) == 5:
                inicio = inicio + ":00"
            if len(fim) == 5:
                fim = fim + ":00"
            capacidade = int(request.form.get("capacidade", "0"))
            local = request.form.get("local", "").strip()
            # Aplica todas as regras antes de executar INSERT ou UPDATE.
            erro = validar_aula(
                id_aula,
                nome,
                modalidade,
                professor,
                dia,
                inicio,
                fim,
                capacidade,
                local,
            )
            if erro:
                con.rollback()
                flash(erro, "erro")
            else:
                if editando:
                    cursor.execute(
                        """UPDATE AULAS
                                      SET NOME = ?, ID_MODALIDADE = ?, ID_PROFESSOR = ?,
                                          DATA_AULA = ?, HORA_INICIO = ?, HORA_FIM = ?,
                                          CAPACIDADE = ?, LOCAL_AULA = ?
                                      WHERE ID_AULA = ?""",
                        (
                            nome,
                            modalidade,
                            professor,
                            dia,
                            inicio,
                            fim,
                            capacidade,
                            local,
                            id_aula,
                        ),
                    )
                else:
                    cursor.execute(
                        """INSERT INTO AULAS (NOME, ID_MODALIDADE, ID_PROFESSOR,
                                          DATA_AULA, HORA_INICIO, HORA_FIM, CAPACIDADE, LOCAL_AULA,
                                          SITUACAO)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AGENDADA')""",
                        (
                            nome,
                            modalidade,
                            professor,
                            dia,
                            inicio,
                            fim,
                            capacidade,
                            local,
                        ),
                    )
                con.commit()
                flash("Aula salva com sucesso!", "sucesso")
                return redirect(url_for("aulas"))
        else:
            con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash(
            "Não foi possível salvar. Confira data, horários, modalidade, professor e capacidade.",
            "erro",
        )
    finally:
        cursor.close()
    return render_template(
        "aula_form.html",
        usuario=usuario,
        item=item,
        modalidades=modos,
        professores=professores,
        editando=editando,
        titulo=titulo,
        modalidade_selecionada=modalidade_selecionada,
        professor_selecionado=professor_selecionado,
        hoje=momento_atual()[0:10],
    )


# Detalhes e cancelamento da aula
# Mostra a aula e as ações disponíveis para o perfil conectado.
@app.route("/aulas/<int:id_aula>")
def aula_detalhes(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    aula = buscar_aula(id_aula)
    if not aula or (usuario[4] == "PERSONAL" and aula[3] != usuario[0]):
        con.rollback()
        flash("Aula não encontrada ou acesso não permitido.", "erro")
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_INSCRICAO
                          FROM INSCRICOES
                          WHERE ID_AULA = ? AND ID_USUARIO = ? AND ATIVA = 1""",
            (id_aula, usuario[0]),
        )
        inscricao = cursor.fetchone()
        inscritos = []
        if usuario[4] != "ALUNO":
            inscritos = buscar_inscritos(id_aula)
        con.commit()
    finally:
        cursor.close()
    return render_template(
        "aula_detalhes.html",
        usuario=usuario,
        aula=aula,
        inscricao=inscricao,
        inscritos=inscritos,
    )


# Cancela a aula sem apagar o registro ou seu histórico.
@app.route("/aulas/<int:id_aula>/cancelar", methods=["GET", "POST"])
def aula_cancelar(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ADMINISTRADOR":
        return redirect(url_for("voltar_home"))
    aula = buscar_aula(id_aula)
    if not aula:
        con.rollback()
        flash("Aula não encontrada.", "erro")
        return redirect(url_for("aulas"))
    if request.method == "POST":
        cursor = con.cursor()
        try:
            cursor.execute(
                """UPDATE AULAS
                              SET SITUACAO = 'CANCELADA'
                              WHERE ID_AULA = ?""",
                (id_aula,),
            )
            con.commit()
            flash("Aula cancelada. O histórico foi preservado.", "sucesso")
            return redirect(url_for("aulas"))
        except Exception as e:
            con.rollback()
            print(e)
            flash("Não foi possível cancelar a aula.", "erro")
        finally:
            cursor.close()
    else:
        con.commit()
    return render_template(
        "confirmar.html",
        usuario=usuario,
        titulo="Cancelar aula",
        mensagem=f"Cancelar a aula {aula[1]}?",
        voltar=url_for("aulas"),
        botao="Cancelar aula",
    )


# Inscrição e vagas
# Inscreve o aluno se a aula estiver disponível e tiver vagas.
@app.route("/aulas/<int:id_aula>/inscrever", methods=["POST"])
def inscrever(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ALUNO":
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        aula = buscar_aula(id_aula)
        erro = ""
        # Confere se a aula está agendada, é futura e pertence a modalidade ativa.
        if not aula or aula[9] != "AGENDADA" or aula[13] != 1 or not aula[17]:
            erro = "Inscrição indisponível para esta aula."
        elif aula[12] >= aula[7]:
            erro = "Aula lotada. Não há vagas disponíveis."
        cursor.execute(
            """SELECT ID_INSCRICAO, ATIVA
                          FROM INSCRICOES
                          WHERE ID_AULA = ? AND ID_USUARIO = ?""",
            (id_aula, usuario[0]),
        )
        inscricao = cursor.fetchone()
        # Impede repetir uma inscrição que já está ativa.
        if inscricao and inscricao[1] == 1:
            erro = "Você já está inscrito nesta aula."
        if erro:
            con.rollback()
            flash(erro, "erro")
        else:
            # Se já houve inscrição cancelada, reativa o registro em vez de duplicá-lo.
            if inscricao:
                cursor.execute(
                    """UPDATE INSCRICOES
                                  SET ATIVA = 1, PRESENTE = ?
                                  WHERE ID_INSCRICAO = ?""",
                    (None, inscricao[0]),
                )
            else:
                cursor.execute(
                    """INSERT INTO INSCRICOES (ID_AULA, ID_USUARIO, ATIVA)
                                  VALUES (?, ?, 1)""",
                    (id_aula, usuario[0]),
                )
            con.commit()
            flash("Inscrição realizada com sucesso!", "sucesso")
    except Exception as e:
        con.rollback()
        print(e)
        flash("Inscrição indisponível. Confira a data da aula e as vagas.", "erro")
    finally:
        cursor.close()
    return redirect(url_for("minhas_aulas"))


# Minhas aulas e cancelamento de inscrição
# Mostra as aulas com inscrição ativa do aluno conectado.
@app.route("/minhas-aulas")
def minhas_aulas():
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ALUNO":
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        cursor.execute(
            """SELECT ID_AULA
                          FROM INSCRICOES
                          WHERE ID_USUARIO = ? AND ATIVA = 1""",
            (usuario[0],),
        )
        inscricoes = cursor.fetchall()
        aulas = []
        for aula in buscar_aulas():
            for inscricao in inscricoes:
                if aula[0] == inscricao[0]:
                    aulas.append(aula)
        con.commit()
    finally:
        cursor.close()
    return render_template("minhas_aulas.html", usuario=usuario, aulas=aulas)


# Desativa a inscrição do aluno e libera a vaga da aula.
@app.route("/inscricoes/<int:id_aula>/cancelar", methods=["GET", "POST"])
def cancelar_inscricao(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] != "ALUNO":
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        aula = buscar_aula(id_aula)
        cursor.execute(
            """SELECT ID_INSCRICAO
                          FROM INSCRICOES
                          WHERE ID_AULA = ? AND ID_USUARIO = ? AND ATIVA = 1""",
            (id_aula, usuario[0]),
        )
        inscricao = cursor.fetchone()
        if not aula or not inscricao:
            con.rollback()
            flash("Inscrição não encontrada.", "erro")
            return redirect(url_for("minhas_aulas"))
        # Somente o envio da confirmação efetiva o cancelamento.
        if request.method == "POST":
            # Mantém o registro e apenas marca a inscrição como inativa.
            cursor.execute(
                """UPDATE INSCRICOES
                              SET ATIVA = 0
                              WHERE ID_INSCRICAO = ?""",
                (inscricao[0],),
            )
            con.commit()
            flash("Inscrição cancelada com sucesso!", "sucesso")
            return redirect(url_for("minhas_aulas"))
        con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash("Não foi possível cancelar a inscrição.", "erro")
        return redirect(url_for("minhas_aulas"))
    finally:
        cursor.close()
    return render_template(
        "confirmar.html",
        usuario=usuario,
        titulo="Cancelar inscrição",
        mensagem=f"Cancelar sua inscrição em {aula[1]}?",
        voltar=url_for("minhas_aulas"),
        botao="Confirmar cancelamento",
    )


# Chamada
# Permite registrar presença nas aulas com a autorização necessária.
@app.route("/chamada/<int:id_aula>", methods=["GET", "POST"])
def chamada(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] not in ("ADMINISTRADOR", "PERSONAL"):
        return redirect(url_for("voltar_home"))
    cursor = con.cursor()
    try:
        aula = buscar_aula(id_aula)
        if not aula or (usuario[4] == "PERSONAL" and aula[3] != usuario[0]):
            con.rollback()
            flash("Aula não encontrada ou acesso não permitido.", "erro")
            return redirect(url_for("voltar_home"))
        inscritos = buscar_inscritos(id_aula)
        if request.method == "POST":
            # Lê a presença de cada aluno e atualiza sua inscrição.
            for inscricao in inscritos:
                valor = request.form.get(f"presenca_{inscricao[0]}", "")
                presente = None
                if valor == "1":
                    presente = 1
                elif valor == "0":
                    presente = 0
                cursor.execute(
                    """UPDATE INSCRICOES
                                  SET PRESENTE = ?
                                  WHERE ID_INSCRICAO = ?""",
                    (presente, inscricao[0]),
                )
            con.commit()
            flash("Chamada salva com sucesso!", "sucesso")
            return redirect(url_for("chamada", id_aula=id_aula))
        con.commit()
    except Exception as e:
        con.rollback()
        print(e)
        flash("Não foi possível carregar ou salvar a chamada.", "erro")
        return redirect(url_for("voltar_home"))
    finally:
        cursor.close()
    return render_template(
        "chamada.html", usuario=usuario, aula=aula, inscritos=inscritos
    )


# Conclusão de aula
# Conclui a aula após seu horário final, preservando os registros.
@app.route("/aulas/<int:id_aula>/concluir", methods=["GET", "POST"])
def aula_concluir(id_aula):
    usuario = buscar_usuario()
    if not usuario:
        return redirect(url_for("login"))
    if usuario[4] not in ("ADMINISTRADOR", "PERSONAL"):
        return redirect(url_for("voltar_home"))
    aula = buscar_aula(id_aula)
    if not aula or (usuario[4] == "PERSONAL" and aula[3] != usuario[0]):
        con.rollback()
        flash("Aula não encontrada ou acesso não permitido.", "erro")
        return redirect(url_for("voltar_home"))
    if aula[9] != "AGENDADA" or not aula[18]:
        con.rollback()
        flash(
            "Só é possível concluir uma aula agendada após seu horário final.", "erro"
        )
        return redirect(url_for("aula_detalhes", id_aula=id_aula))
    if request.method == "POST":
        cursor = con.cursor()
        try:
            # Marca a conclusão sem excluir a aula nem suas inscrições.
            cursor.execute(
                """UPDATE AULAS
                              SET SITUACAO = 'CONCLUIDA'
                              WHERE ID_AULA = ?""",
                (id_aula,),
            )
            con.commit()
            flash(
                "Aula concluída. Inscrições e presenças foram preservadas.", "sucesso"
            )
            return redirect(url_for("aula_detalhes", id_aula=id_aula))
        except Exception as e:
            con.rollback()
            print(e)
            flash(
                "Não foi possível concluir a aula. Confira as informações no terminal.",
                "erro",
            )
        finally:
            cursor.close()
    else:
        con.commit()
    return render_template(
        "confirmar.html",
        usuario=usuario,
        titulo="Concluir aula",
        mensagem=f"Concluir a aula {aula[1]}?",
        voltar=url_for("aula_detalhes", id_aula=id_aula),
        botao="Concluir aula",
    )


# Erro de conexão
# Desfaz a transação pendente e mostra uma página de erro do banco.
@app.errorhandler(fdb.DatabaseError)
def erro_banco(erro):
    try:
        con.rollback()
    except Exception:
        pass
    print(erro)
    return (
        render_template(
            "erro.html",
            titulo="Falha no banco de dados",
            mensagem="Não foi possível concluir a operação. Confira a conexão e o erro no terminal.",
        ),
        503,
    )


# Execução
# Inicia o servidor somente quando este arquivo é executado diretamente.
if __name__ == "__main__":
    app.run(threaded=False)
