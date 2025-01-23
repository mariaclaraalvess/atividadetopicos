<?php
// Conectar ao banco de dados
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "atvd_db"; // Substitua por o nome do banco de dados que você criou

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Falha na conexão: " . $conn->connect_error);
}

// Função para validar e higienizar entradas
function limparEntrada($dados) {
  $dados = trim($dados);
  $dados = stripslashes($dados);
  $dados = htmlspecialchars($dados);
  return $dados;
}

// Função para validar o formato de e-mail
function validarEmail($email) {
  return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Função para validar a senha
function validarSenha($senha) {
  // A senha precisa ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial
  $padrao = "/^(?=.*[A-Za-z])(?=.*\d)(?=.*[!$%^&*?])[A-Za-z\d!$%^&*?]{8,}$/";
  return preg_match($padrao, $senha);
}

// Verificar se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $nome = limparEntrada($_POST['nome']);
  $email = limparEntrada($_POST['email']);
  $senha = limparEntrada($_POST['senha']);
  $confirma_senha = limparEntrada($_POST['confirma_senha']);
  $termos = isset($_POST['termos']) ? true : false;

  // Validar se os termos foram aceitos
  if (!$termos) {
    echo "Você precisa aceitar os termos e condições.";
    exit();
  }

  // Validar o e-mail
  if (!validarEmail($email)) {
    echo "Por favor, insira um e-mail válido.";
    exit();
  }

  // Validar se as senhas coincidem
  if ($senha !== $confirma_senha) {
    echo "As senhas não coincidem!";
    exit();
  }

  // Validar a senha
  if (!validarSenha($senha)) {
    echo "A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.";
    exit();
  }

  // Validar e verificar se o e-mail já está cadastrado
  $stmt = $conn->prepare("SELECT id FROM usuarios WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $stmt->store_result();

  if ($stmt->num_rows > 0) {
    echo "E-mail já está em uso!";
    exit();
  }

  // Gerar o hash da senha usando bcrypt
  $hash_senha = password_hash($senha, PASSWORD_BCRYPT);

  // Inserir o novo usuário no banco de dados
  $stmt = $conn->prepare("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)");
  $stmt->bind_param("sss", $nome, $email, $hash_senha);

  if ($stmt->execute()) {
    echo "Cadastro realizado com sucesso!";
  } else {
    echo "Erro ao cadastrar: " . $stmt->error;
  }

  $stmt->close();
}

$conn->close();
?>
