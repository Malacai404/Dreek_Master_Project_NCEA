
CREATE TABLE IF NOT EXISTS `category` (
    `category_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
    `category_name` TEXT NOT NULL,
    `video_count` INTEGER DEFAULT 0,
    `category_image_link` TEXT NOT NULL,
    `description` TEXT NOT NULL
);


INSERT OR IGNORE INTO `category` (`category_id`, `category_name`, `video_count`, `category_image_link`, `description`) VALUES
(1, 'Technology', 2, 'https://example.com/images/technology.jpg', 'Explore the latest in tech.'),
(2, 'Cooking', 1, 'https://example.com/images/cooking.jpg', 'Delicious recipes and cooking tips.'),
(3, 'Gaming', 3, 'https://example.com/images/gaming.jpg', 'Gaming news and walkthroughs.');


CREATE TABLE IF NOT EXISTS `channel` (
    `channel_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
    `channel_name` TEXT NOT NULL,
    `follow_count` INTEGER DEFAULT 0,
    `channel_image_link` TEXT NOT NULL,
    `description` TEXT NOT NULL,
    `video_count` INTEGER DEFAULT 0,
    `primary_category_id` INTEGER REFERENCES `category`(`category_id`)
);


INSERT OR IGNORE INTO `channel` (`channel_id`, `channel_name`, `follow_count`, `channel_image_link`, `description`, `video_count`, `primary_category_id`) VALUES
(1, 'TechReviews', 1200, 'https://example.com/images/techreviews.jpg', 'Tech reviews and gadget unboxings.', 2, 1),
(2, 'CookingWithEmma', 3400, 'https://example.com/images/cookingwithemma.jpg', 'Delicious recipes and cooking tips.', 1, 2),
(3, 'GamingUniverse', 5000, 'https://example.com/images/gaminguniverse.jpg', 'Gaming news and walkthroughs.', 3, 3);


CREATE TABLE IF NOT EXISTS `video` (
    `video_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
    `view_count` INTEGER DEFAULT 0,
    `video_file_link` TEXT NOT NULL,
    `description` TEXT NOT NULL,
    `video_length` TEXT NOT NULL,
    `comments_list_id` INTEGER REFERENCES `comments_list`(`comments_list_id`),
    `category_id` INTEGER REFERENCES `category`(`category_id`),
    `channel_id` INTEGER REFERENCES `channel`(`channel_id`),
    `video_thumbnail_file_link` TEXT NOT NULL
);


INSERT OR IGNORE INTO `video` (`video_id`, `view_count`, `video_file_link`, `description`, `video_length`, `comments_list_id`, `category_id`, `channel_id`, `video_thumbnail_file_link`) VALUES
(1, 1200, 'https://example.com/videos/video1.mp4', 'Amazing Tech Gadgets You Need in 2023', '10:30', 1, 1, 1, 'https://example.com/thumbnails/video1.jpg'),
(2, 3400, 'https://example.com/videos/video2.mp4', 'New Game Release: Ultimate Review', '22:18', 2, 3, 3, 'https://example.com/thumbnails/video2.jpg'),
(3, 500, 'https://example.com/videos/video3.mp4', 'Delicious Pasta Recipe', '15:45', 3, 2, 2, 'https://example.com/thumbnails/video3.jpg');


CREATE TABLE IF NOT EXISTS `comments_list` (
    `comments_list_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE
);


CREATE TABLE IF NOT EXISTS `comment` (
    `comment_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
    `comment_text` TEXT NOT NULL,
    `user_info_id` INTEGER REFERENCES `user_info`(`user_info_id`)
);


INSERT OR IGNORE INTO `comment` (`comment_id`, `comment_text`, `user_info_id`) VALUES
(1, 'Great video!', 1),
(2, 'Very informative, thanks!', 2),
(3, 'Loved this content!', 3);


CREATE TABLE IF NOT EXISTS `user_info` (
    `user_info_id` INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
    `username` TEXT NOT NULL,
    `email` TEXT UNIQUE NOT NULL,
    `password` TEXT NOT NULL,
    `verified` TEXT NOT NULL,
    `channel_id` INTEGER UNIQUE REFERENCES `channel`(`channel_id`)
);


INSERT OR IGNORE INTO `user_info` (`user_info_id`, `username`, `email`, `password`, `verified`, `channel_id`) VALUES
(1, 'JohnDoe', 'johndoe@example.com', 'hashed_password_1', '1', 1),
(2, 'EmmaChef', 'emmachef@example.com', 'hashed_password_2', '1', 2),
(3, 'GamerGuy', 'gamerguy@example.com', 'hashed_password_3', '1', 3);