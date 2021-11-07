## Apache Shiro

# 1. Visão Geral
Neste artigo, veremos o Apache Shiro, uma estrutura de segurança Java versátil.

O framework é altamente customizável e modular, pois oferece autenticação, autorização, criptografia e gerenciamento de sessão.

# 2. Dependência
O Apache Shiro possui muitos módulos. No entanto, neste tutorial, usamos apenas o artefato shiro-core.

Vamos adicioná-lo ao nosso pom.xml:

```
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.4.0</version>
</dependency>
```

A versão mais recente dos módulos do Apache Shiro pode ser encontrada no Maven Central.

# 3. Configurando o Security Manager
O SecurityManager é a peça central da estrutura do Apache Shiro. Os aplicativos geralmente terão uma única instância em execução.

Neste tutorial, exploramos a estrutura em um ambiente de desktop. Para configurar a estrutura, precisamos criar um arquivo shiro.ini na pasta de recursos com o seguinte conteúdo:

```
[users]
user = password, admin
user2 = password2, editor
user3 = password3, author

[roles]
admin = *
editor = articles:*
author = articles:compose,articles:save
```

A seção [usuários] do arquivo de configuração shiro.ini define as credenciais do usuário que são reconhecidas pelo SecurityManager. O formato é: principal (nome de usuário) = senha, função1, função2,…, função.

As funções e suas permissões associadas são declaradas na seção [funções]. A função de administrador recebe permissão e acesso a todas as partes do aplicativo. Isso é indicado pelo símbolo curinga (*).

A função de editor possui todas as permissões associadas aos artigos, enquanto a função de autor pode apenas redigir e salvar um artigo.

O SecurityManager é usado para configurar a classe SecurityUtils. A partir do SecurityUtils podemos obter o usuário atual interagindo com o sistema e realizar operações de autenticação e autorização.

Vamos usar o IniRealm para carregar nossas definições de usuário e função do arquivo shiro.ini e, em seguida, usá-lo para configurar o objeto DefaultSecurityManager:

```
IniRealm iniRealm = new IniRealm("classpath:shiro.ini");
SecurityManager securityManager = new DefaultSecurityManager(iniRealm);

SecurityUtils.setSecurityManager(securityManager);
Subject currentUser = SecurityUtils.getSubject();
```

Agora que temos um SecurityManager que está ciente das credenciais e funções do usuário definidas no arquivo shiro.ini, vamos prosseguir para a autenticação e autorização do usuário.

# 4. Autenticação
Nas terminologias do Apache Shiro, um Assunto é qualquer entidade que interage com o sistema. Pode ser um humano, um script ou um cliente REST.

Chamar SecurityUtils.getSubject() retorna uma instância do Assunto atual, ou seja, o currentUser.

Agora que temos o objeto currentUser, podemos realizar a autenticação nas credenciais fornecidas:

```
if (!currentUser.isAuthenticated()) {               
  UsernamePasswordToken token                       
    = new UsernamePasswordToken("user", "password");
  token.setRememberMe(true);                        
  try {                                             
      currentUser.login(token);                       
  } catch (UnknownAccountException uae) {           
      log.error("Username Not Found!", uae);        
  } catch (IncorrectCredentialsException ice) {     
      log.error("Invalid Credentials!", ice);       
  } catch (LockedAccountException lae) {            
      log.error("Your Account is Locked!", lae);    
  } catch (AuthenticationException ae) {            
      log.error("Unexpected Error!", ae);           
  }                                                 
}
```

Primeiro, verificamos se o usuário atual ainda não foi autenticado. Em seguida, criamos um token de autenticação com o usuário principal (nome de usuário) e credencial (senha).

Em seguida, tentamos fazer login com o token. Se as credenciais fornecidas estiverem corretas, tudo deve correr bem.

Existem diferentes exceções para diferentes casos. Também é possível lançar uma exceção personalizada que melhor se adapte aos requisitos do aplicativo. Isso pode ser feito criando uma subclasse da classe AccountException.

# 5. Autorização
A autenticação está tentando validar a identidade de um usuário enquanto a autorização tenta controlar o acesso a determinados recursos no sistema.

Lembre-se de que atribuímos uma ou mais funções a cada usuário que criamos no arquivo shiro.ini. Além disso, na seção de funções, definimos diferentes permissões ou níveis de acesso para cada função.

Agora vamos ver como podemos usar isso em nosso aplicativo para impor o controle de acesso do usuário.

No arquivo shiro.ini, damos ao administrador acesso total a todas as partes do sistema.

O editor tem acesso total a todos os recursos / operações referentes aos artigos, sendo que o autor fica restrito a apenas redigir e salvar apenas os artigos.

Vamos dar as boas-vindas ao usuário atual com base na função:

```
if (currentUser.hasRole("admin")) {       
    log.info("Welcome Admin");              
} else if(currentUser.hasRole("editor")) {
    log.info("Welcome, Editor!");           
} else if(currentUser.hasRole("author")) {
    log.info("Welcome, Author");            
} else {                                  
    log.info("Welcome, Guest");             
}
```

Agora, vamos ver o que o usuário atual tem permissão para fazer no sistema:

```
if(currentUser.isPermitted("articles:compose")) {            
    log.info("You can compose an article");                    
} else {                                                     
    log.info("You are not permitted to compose an article!");
}                                                            
                                                             
if(currentUser.isPermitted("articles:save")) {               
    log.info("You can save articles");                         
} else {                                                     
    log.info("You can not save articles");                   
}                                                            
                                                             
if(currentUser.isPermitted("articles:publish")) {            
    log.info("You can publish articles");                      
} else {                                                     
    log.info("You can not publish articles");                
}
```

# 6. Configuração do Reino
Em aplicativos reais, precisaremos de uma maneira de obter as credenciais do usuário de um banco de dados, em vez do arquivo shiro.ini. É aqui que o conceito de Reino entra em jogo.

Na terminologia do Apache Shiro, um Realm é um DAO que aponta para um armazenamento de credenciais de usuário necessárias para autenticação e autorização.

Para criar um realm, precisamos apenas implementar a interface Realm. Isso pode ser entediante; no entanto, a estrutura vem com implementações padrão das quais podemos criar uma subclasse. Uma dessas implementações é JdbcRealm.

Criamos uma implementação de domínio customizada que estende a classe JdbcRealm e substitui os seguintes métodos: doGetAuthenticationInfo(), doGetAuthorizationInfo(), getRoleNamesForUser() e getPermissions().

Vamos criar um reino criando uma subclasse da classe JdbcRealm:

```
public class MyCustomRealm extends JdbcRealm {
    //...
}
```

Para simplificar, usamos java.util.Map para simular um banco de dados:

```
private Map<String, String> credentials = new HashMap<>();
private Map<String, Set<String>> roles = new HashMap<>();
private Map<String, Set<String>> perm = new HashMap<>();

{
    credentials.put("user", "password");
    credentials.put("user2", "password2");
    credentials.put("user3", "password3");
                                          
    roles.put("user", new HashSet<>(Arrays.asList("admin")));
    roles.put("user2", new HashSet<>(Arrays.asList("editor")));
    roles.put("user3", new HashSet<>(Arrays.asList("author")));
                                                             
    perm.put("admin", new HashSet<>(Arrays.asList("*")));
    perm.put("editor", new HashSet<>(Arrays.asList("articles:*")));
    perm.put("author", 
      new HashSet<>(Arrays.asList("articles:compose", 
      "articles:save")));
}
```

Vamos prosseguir e substituir o doGetAuthenticationInfo():

```
protected AuthenticationInfo 
  doGetAuthenticationInfo(AuthenticationToken token)
  throws AuthenticationException {
                                                                 
    UsernamePasswordToken uToken = (UsernamePasswordToken) token;
                                                                
    if(uToken.getUsername() == null
      || uToken.getUsername().isEmpty()
      || !credentials.containsKey(uToken.getUsername())) {
          throw new UnknownAccountException("username not found!");
    }
                                        
    return new SimpleAuthenticationInfo(
      uToken.getUsername(), 
      credentials.get(uToken.getUsername()), 
      getName()); 
}
```

Primeiro, lançamos o AuthenticationToken fornecido para UsernamePasswordToken. Do uToken, extraímos o nome de usuário (uToken.getUsername()) e o usamos para obter as credenciais do usuário (senha) do banco de dados.

Se nenhum registro for encontrado - lançamos um UnknownAccountException, caso contrário, usamos a credencial e o nome de usuário para construir um objeto SimpleAuthenticatioInfo que é retornado do método.

Se a credencial do usuário for hash com um salt, precisamos retornar um SimpleAuthenticationInfo com o salt associado:

```
return new SimpleAuthenticationInfo(
  uToken.getUsername(), 
  credentials.get(uToken.getUsername()), 
  ByteSource.Util.bytes("salt"), 
  getName()
);
```

Também precisamos substituir doGetAuthorizationInfo(), bem como getRoleNamesForUser() e getPermissions().

Finalmente, vamos conectar o domínio customizado ao securityManager. Tudo o que precisamos fazer é substituir o IniRealm acima pelo nosso domínio personalizado e passá-lo para o construtor do DefaultSecurityManager:

```
Realm realm = new MyCustomRealm();
SecurityManager securityManager = new DefaultSecurityManager(realm);
```

Every other part of the code is the same as before. This is all we need to configure the securityManager with a custom realm properly.


freestar
Now the question is – how does the framework match the credentials?

By default, the JdbcRealm uses the SimpleCredentialsMatcher, which merely checks for equality by comparing the credentials in the AuthenticationToken and the AuthenticationInfo.

If we hash our passwords, we need to inform the framework to use a HashedCredentialsMatcher instead. The INI configurations for realms with hashed passwords can be found here.

# 7. Logging Out
Now that we've authenticated the user, it's time to implement log out. That's done simply by calling a single method – which invalidates the user session and logs the user out:

```
currentUser.logout();
```

# 8. Gerenciamento de Sessão
O framework vem naturalmente com seu sistema de gerenciamento de sessão. Se usado em um ambiente da web, o padrão é a implementação HttpSession.

Para um aplicativo independente, ele usa seu sistema de gerenciamento de sessão corporativa. O benefício é que, mesmo em um ambiente de desktop, você pode usar um objeto de sessão como faria em um ambiente típico da Web.

Vamos dar uma olhada em um exemplo rápido e interagir com a sessão do usuário atual:

```
Session session = currentUser.getSession();                
session.setAttribute("key", "value");                      
String value = (String) session.getAttribute("key");       
if (value.equals("value")) {                               
    log.info("Retrieved the correct value! [" + value + "]");
}
```

# 9. Shiro para um aplicativo da Web com Spring
Até agora, descrevemos a estrutura básica do Apache Shiro e a implementamos em um ambiente de desktop. Vamos prosseguir integrando a estrutura em um aplicativo Spring Boot.

Observe que o foco principal aqui é Shiro, não o aplicativo Spring - vamos usar isso apenas para alimentar um aplicativo de exemplo simples.

### 9.1 Dependências
Primeiro, precisamos adicionar a dependência pai Spring Boot ao nosso pom.xml:

```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.5.1</version>
</parent>
```

Em seguida, temos que adicionar as seguintes dependências ao mesmo arquivo pom.xml:

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-freemarker</artifactId>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring-boot-web-starter</artifactId>
    <version>${apache-shiro-core-version}</version>
</dependency>
```

### 9.2. Configuração
Adicionar a dependência shiro-spring-boot-web-starter ao nosso pom.xml configurará por padrão alguns recursos do aplicativo Apache Shiro, como o SecurityManager.

No entanto, ainda precisamos configurar os filtros de segurança Realm e Shiro. Estaremos usando o mesmo domínio personalizado definido acima.

E assim, na classe principal onde o aplicativo Spring Boot é executado, vamos adicionar as seguintes definições de Bean:

```
@Bean
public Realm realm() {
    return new MyCustomRealm();
}
    
@Bean
public ShiroFilterChainDefinition shiroFilterChainDefinition() {
    DefaultShiroFilterChainDefinition filter
      = new DefaultShiroFilterChainDefinition();

    filter.addPathDefinition("/secure", "authc");
    filter.addPathDefinition("/**", "anon");

    return filter;
}
```

No ShiroFilterChainDefinition, aplicamos o filtro authc ao caminho / seguro e aplicamos o filtro anon em outros caminhos usando o padrão Ant.

Os filtros authc e anon vêm por padrão para aplicativos da web. Outros filtros padrão podem ser encontrados aqui.

Se não definimos o bean Realm, ShiroAutoConfiguration irá, por padrão, fornecer uma implementação IniRealm que espera encontrar um arquivo shiro.ini em src/main/resources ou src/main/resources/META-INF.

Se não definirmos um bean ShiroFilterChainDefinition, a estrutura protege todos os caminhos e define a URL de login como login.jsp.

Podemos alterar este URL de login padrão e outros padrões, adicionando as seguintes entradas ao nosso application.properties:

```
shiro.loginUrl = /login
shiro.successUrl = /secure
shiro.unauthorizedUrl = /login
```

Agora que o filtro authc foi aplicado a / secure, todas as solicitações para essa rota exigirão uma autenticação de formulário.

### 9.3. Autenticação e autorização
Vamos criar um ShiroSpringController com os seguintes mapeamentos de caminho: /index, /login, /logout e /secure.

O método login() é onde implementamos a autenticação do usuário real conforme descrito acima. Se a autenticação for bem-sucedida, o usuário será redirecionado para a página segura:

```
Subject subject = SecurityUtils.getSubject();

if(!subject.isAuthenticated()) {
    UsernamePasswordToken token = new UsernamePasswordToken(
      cred.getUsername(), cred.getPassword(), cred.isRememberMe());
    try {
        subject.login(token);
    } catch (AuthenticationException ae) {
        ae.printStackTrace();
        attr.addFlashAttribute("error", "Invalid Credentials");
        return "redirect:/login";
    }
}

return "redirect:/secure";
```

E agora, na implementação secure(), o currentUser foi obtido invocando o SecurityUtils.getSubject(). A função e as permissões do usuário são passadas para a página segura, assim como o principal do usuário:

```
Subject currentUser = SecurityUtils.getSubject();
String role = "", permission = "";

if(currentUser.hasRole("admin")) {
    role = role  + "You are an Admin";
} else if(currentUser.hasRole("editor")) {
    role = role + "You are an Editor";
} else if(currentUser.hasRole("author")) {
    role = role + "You are an Author";
}

if(currentUser.isPermitted("articles:compose")) {
    permission = permission + "You can compose an article, ";
} else {
    permission = permission + "You are not permitted to compose an article!, ";
}

if(currentUser.isPermitted("articles:save")) {
    permission = permission + "You can save articles, ";
} else {
    permission = permission + "\nYou can not save articles, ";
}

if(currentUser.isPermitted("articles:publish")) {
    permission = permission  + "\nYou can publish articles";
} else {
    permission = permission + "\nYou can not publish articles";
}

modelMap.addAttribute("username", currentUser.getPrincipal());
modelMap.addAttribute("permission", permission);
modelMap.addAttribute("role", role);

return "secure";
```

E terminamos. É assim que podemos integrar o Apache Shiro em um aplicativo Spring Boot.

Além disso, observe que a estrutura oferece anotações adicionais que podem ser usadas junto com as definições da cadeia de filtros para proteger nosso aplicativo.

# 10. Integração JEE
A integração do Apache Shiro em um aplicativo JEE é apenas uma questão de configuração do arquivo web.xml. Como de costume, a configuração espera que o shiro.ini esteja no caminho da classe. Um exemplo de configuração detalhado está disponível aqui. Além disso, as tags JSP podem ser encontradas aqui.

# 11. Conclusão
Neste tutorial, vimos os mecanismos de autenticação e autorização do Apache Shiro. Também nos concentramos em como definir um domínio personalizado e conectá-lo ao SecurityManager.
