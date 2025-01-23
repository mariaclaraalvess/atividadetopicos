<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "atvd_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Falha na conexão: " . $conn->connect_error);
}

function limparEntrada($dados) {
  $dados = trim($dados);
  $dados = stripslashes($dados);
  $dados = htmlspecialchars($dados);
  return $dados;
}

function validarEmail($email) {
  return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validarSenha($senha) {
  $padrao = "/^(?=.*[A-Za-z])(?=.*\d)(?=.*[!$%^&*?])[A-Za-z\d!$%^&*?]{8,}$/";
  return preg_match($padrao, $senha);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $nome = limparEntrada($_POST['nome']);
  $email = limparEntrada($_POST['email']);
  $senha = limparEntrada($_POST['senha']);
  $confirma_senha = limparEntrada($_POST['confirma_senha']);
  $termos = isset($_POST['termos']) ? true : false;

  if (!$termos) {
    echo "Você precisa aceitar os termos e condições.";
    exit();
  }

  if (!validarEmail($email)) {
    echo "Por favor, insira um e-mail válido.";
    exit();
  }

  if ($senha !== $confirma_senha) {
    echo "As senhas não coincidem!";
    exit();
  }

  if (!validarSenha($senha)) {
    echo "A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.";
    exit();
  }

  $stmt = $conn->prepare("SELECT id FROM usuarios WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $stmt->store_result();

  if ($stmt->num_rows > 0) {
    echo "E-mail já está em uso!";
    exit();
  }

  $hash_senha = password_hash($senha, PASSWORD_BCRYPT);

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
