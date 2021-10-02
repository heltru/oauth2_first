-- phpMyAdmin SQL Dump
-- version 4.8.3
-- https://www.phpmyadmin.net/
--
-- Хост: 127.0.0.1:3306
-- Время создания: Окт 02 2021 г., 04:51
-- Версия сервера: 5.6.41
-- Версия PHP: 7.2.10

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- База данных: `ismeta`
--

-- --------------------------------------------------------

--
-- Структура таблицы `oauth_authorization_codes`
--

CREATE TABLE `oauth_authorization_codes` (
  `authorization_code` varchar(40) NOT NULL,
  `client_id` varchar(32) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `redirect_uri` varchar(1000) NOT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Дамп данных таблицы `oauth_authorization_codes`
--

INSERT INTO `oauth_authorization_codes` (`authorization_code`, `client_id`, `user_id`, `redirect_uri`, `expires`, `scope`) VALUES
('0558f11bb8df586ace5ea0fe27f996285d805bc6', 'testclient', 32, 'http://fake/', '2021-09-30 01:19:22', 'photo'),
('0815a298de8273119ba798ee9dda8e2b1e0f35ff', 'testclient', 32, 'http://fake/', '2021-09-29 19:05:12', NULL),
('11fba8b157ff7f116a4723084786b8a3d2e3da67', 'testclient', 32, 'http://fake/', '2021-09-29 20:00:11', 'photo'),
('147d7d7de5952ce344bc2e0a9d24d2cc1d7ba6b2', 'testclient', 32, 'http://fake/', '2021-09-29 20:21:58', 'photo'),
('18f0ab8a3b8ecbf4836827e7e4d70ef21f8552c9', 'testclient', 32, 'http://fake/', '2021-09-30 02:54:54', 'photo'),
('1dc9da967c7a0bf15e2a2135c33fbaec49e8f24d', 'testclient', 32, 'http://fake/', '2021-09-30 01:48:42', 'photo'),
('1f1aa6a7685af7dc9369b2a3ccda4fcfdd4765bc', 'testclient', 32, 'http://fake/', '2021-09-29 21:23:00', 'photo'),
('1f9572946684b4b15d8b01cd427fb378def07fd8', 'testclient', 32, 'http://fake/', '2021-10-02 01:32:52', NULL),
('20a5c5a70e2cd0d72f01f3fd544212d271c0d60a', 'testclient', 32, 'http://fake/', '2021-09-29 21:42:50', 'photo'),
('34f60ddd47a365d841131420d7de8c97da3b086c', 'testclient', 32, 'http://fake/', '2021-09-29 19:53:55', 'photo'),
('3aa19879005b050a1bec1426ca3b89c1efcbd12b', 'testclient', 32, 'http://fake/', '2021-09-30 02:42:40', 'photo'),
('410fba7f5a295369a945727e0d3c1b9f91d6dfcf', 'testclient', 32, 'http://fake/', '2021-09-30 00:13:51', 'photo'),
('437a10100997dce2d4356c8dc4cd6f8d92e5e3de', 'testclient', 32, 'http://fake/', '2021-09-29 19:48:54', 'photo'),
('4487bcddbaf9161158369196e66403fe379b4dd7', 'testclient', 32, 'http://fake/', '2021-09-29 23:27:33', 'photo'),
('5096ee8eabc4f182ef5366b24e60e115442abb1e', 'testclient', 32, 'http://fake/', '2021-09-29 21:41:33', 'photo'),
('5f05c6def69b438c875c38bf89744723b78ac4df', 'testclient', 32, 'http://fake/', '2021-09-29 21:25:53', 'photo'),
('5f98a455aea985b5c3ae656a509bb7b4f231242e', 'testclient', 32, 'http://fake/', '2021-09-30 02:10:48', 'photo'),
('61b4bc700c376c553569d705f4c8d33b321f02c9', 'testclient', 32, 'http://fake/', '2021-09-29 21:56:00', 'photo'),
('66f41146525d2e850c777e355b5823f0059cf0a1', 'testclient', 32, 'http://fake/', '2021-09-30 01:22:55', 'photo'),
('6869248be218850d62a03e39c18fe492d07ba09f', 'testclient', 32, 'http://fake/', '2021-10-01 20:48:07', 'photo'),
('745ed231f7d6702aa791abe6d02f1e43f343861c', 'testclient', 32, 'http://fake/', '2021-09-29 20:20:56', 'photo'),
('750b84f785fabd5cca06c470ea2d75e26a34514d', 'testclient', 32, 'http://fake/', '2021-09-30 02:54:32', 'photo'),
('7921ab55b1f1def9a21d632790981ede90b3b671', 'testclient', 32, 'http://fake/', '2021-09-29 19:48:44', 'photo'),
('8542c2245ff25a394685a3ca041b5d5a7dd54b03', 'testclient', 32, 'http://fake/', '2021-09-29 19:05:07', NULL),
('941c3d4528e8e6f8164492982ad1138e8bb11186', 'testclient', 32, 'http://fake/', '2021-10-02 01:07:16', NULL),
('9506f81be2658153d8d881170e2f916f39df270b', 'testclient', 32, 'http://fake/', '2021-09-29 19:39:39', NULL),
('9caaa05b2786a414262bc7fa3203d924bdabdcea', 'testclient', 32, 'http://fake/', '2021-09-29 19:53:51', 'photo'),
('a05ac3c4d214817330ad257f86e067e45cccd7c2', 'testclient', 32, 'http://fake/', '2021-09-29 19:52:19', 'photo'),
('a2210c8ca6656a4420f152d163c427b8cf61f2dc', 'testclient', 32, 'http://fake/', '2021-09-29 21:41:52', 'photo'),
('b2dc00324773707ee2c26ae20ee4c2484f01990d', 'testclient', 32, 'http://fake/', '2021-09-30 01:18:38', 'photo'),
('bdf3eab4cb69e4b05aca8fc1c161e6c6900f4292', 'testclient', 32, 'http://fake/', '2021-09-29 21:25:32', 'photo'),
('c32d5444fa30cdb32948a15db4dafd4f74eebeb1', 'testclient', 32, 'http://fake/', '2021-09-29 19:59:39', 'photo'),
('c358bb4aa18b12d10e0706ddecf63064956e5a25', 'testclient', 32, 'http://fake/', '2021-09-30 01:20:08', 'photo'),
('cc1ebd40e0a6c105b3ea5ab05f4fa1e33943b1d2', 'testclient', 32, 'http://fake/', '2021-09-29 20:20:58', 'photo'),
('d8bba43e0e7d6869386164cfd897cae0682c1be5', 'testclient', 32, 'http://fake/', '2021-10-01 17:22:20', 'photo'),
('d9645bd641583ff569edb850aa4642a041705929', 'testclient', 32, 'http://fake/', '2021-09-29 21:26:36', 'photo'),
('df39e5ab049d6f600beafc063c74ec16a7b97228', 'testclient', 32, 'http://fake/', '2021-09-30 01:44:28', 'photo'),
('df9ae33ebd71420a03f92a3b9320769d994f1a88', 'testclient', 32, 'http://fake/', '2021-09-29 20:05:07', 'photo'),
('e5948f443a8fe2c39b95384ff779c8940d8198a6', 'testclient', 32, 'http://fake/', '2021-09-30 01:21:21', 'photo'),
('e6b42075af34f9c5ad237200c3caf01989de4506', 'testclient', 32, 'http://fake/', '2021-09-29 21:41:02', 'photo'),
('f28ea5170a42560ed9ba0e9567c5a30ecc83cd1a', 'testclient', 32, 'http://fake/', '2021-09-29 19:45:50', 'photo'),
('fff022673208a07a7aae92996eb793302bd37174', 'testclient', 32, 'http://fake/', '2021-10-01 22:21:51', 'photo');

--
-- Индексы сохранённых таблиц
--

--
-- Индексы таблицы `oauth_authorization_codes`
--
ALTER TABLE `oauth_authorization_codes`
  ADD PRIMARY KEY (`authorization_code`),
  ADD KEY `client_id` (`client_id`);

--
-- Ограничения внешнего ключа сохраненных таблиц
--

--
-- Ограничения внешнего ключа таблицы `oauth_authorization_codes`
--
ALTER TABLE `oauth_authorization_codes`
  ADD CONSTRAINT `oauth_authorization_codes_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`client_id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
