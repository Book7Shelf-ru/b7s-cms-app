// Добро пожаловать на некоторую аутентификацию для Keystone
//
// Это использует @keystone-6/auth для добавления следующего
// - Страница входа в ваш пользовательский интерфейс администратора
// - Стратегия сеанса без сохранения состояния на основе файлов cookie
// - Использование электронной почты пользователя в качестве идентификатора
// - срок действия файлов cookie составляет 30 дней
//
// Этот файл не настраивает то, что могут делать пользователи, и по умолчанию для этого стартера
// project предназначен для того, чтобы позволить любому - вошедшему в систему или нет - что-либо делать.
//
// Если вы хотите предотвратить доступ случайных людей в Интернете к вашим данным,
// вы можете узнать, как это сделать, прочитав https://keystonejs.com/docs/guides/auth-and-access-control
//
// Если вы хотите узнать больше о том, как работает наша готовая аутентификация, пожалуйста
// читать https://keystonejs.com/docs/apis/auth#authentication-api

import { randomBytes } from 'crypto';
import { createAuth } from '@keystone-6/auth';

// видишь https://keystonejs.com/docs/apis/session для документов сеанса
import { statelessSessions } from '@keystone-6/core/session';

// для сеанса без состояния всегда следует предоставлять SESSION_SECRET
// особенно в рабочей среде (сеансы без сохранения состояния будут выданы, если значение SESSION_SECRET не определено)
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && process.env.NODE_ENV !== 'production') {
  sessionSecret = randomBytes(32).toString('hex');
}

// without - это функция, которую мы можем использовать для переноса нашей базовой конфигурации
const { withAuth } = createAuth({
  listKey: 'User',
  identityField: 'email',

// это фрагмент запроса GraphQL для извлечения того, какие данные будут прикреплены к context.session
  // это может быть полезно, когда вы пишете свои функции контроля доступа
  // вы можете узнать больше по адресу https://keystonejs.com/docs/guides/auth-and-access-control
  sessionData: 'name createdAt',
  secretField: 'password',

// // ПРЕДУПРЕЖДЕНИЕ: удалите функциональность первого элемента инициализации в рабочей среде
  // посмотреть https://keystonejs.com/docs/config/auth#init-first-item для большего
  initFirstItem: {
// если в базе данных нет элементов, настроив это поле
    // // вы просите пользовательский интерфейс администратора Keystone создать нового пользователя
    // предоставление входных данных для этих полей
    fields: ['name', 'email', 'password'],

    // it uses context.sudo() to do this, which bypasses any access control you might have
    //   you shouldn't use this in production
  },
});

// сеансы без сохранения состояния используют файлы cookie для отслеживания сеансов
// срок действия этих файлов cookie исчисляется секундами
// срок годности этой закваски истекает через 30 дней
const sessionMaxAge = 60 * 60 * 24 * 30;

// вы можете узнать больше на https://keystonejs.com/docs/apis/session#session-api
const session = statelessSessions({
  maxAge: sessionMaxAge,
  secret: sessionSecret!,
});

export { withAuth, session };
