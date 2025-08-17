require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express')
const app = express()
const cors = require('cors')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);
const port = process.env.PORT || 5000

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174', 'https://super-gelato-a1166f.netlify.app'],
    credentials: true
}))
app.use(express.json());
app.use(cookieParser());



const verifyToken = (req, res, next) => {
    const token = req?.cookies?.token;
    // console.log('inside the middleware', token)

    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' })
    }

    // verify token
    jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next()
    })
}




const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zffyl01.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});


async function run() {
    try {
        // await client.connect();

        const db = client.db('chatorbit');
        const usersCollection = db.collection('users');
        const postsCollection = db.collection('posts');
        const commentCollection = db.collection('comments');
        const reportCollection = db.collection('reports')
        const announcementCollection = db.collection('announcements')
        const tagCollection = db.collection('tags')

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email }
            const user = await usersCollection.findOne(query);
            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'forbidden access' })
            }
            next();
        }


        // jwt token related api
        app.post('/jwt', async (req, res) => {
            const { email } = req.body;
            const user = { email }
            const token = jwt.sign(user, process.env.JWT_ACCESS_SECRET, { expiresIn: '1d' });

            // set token in the server
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production" ? true : false,
                sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
                maxAge: 24 * 60 * 60 * 1000
            })
            res.send({ success: true })
        })

        // jwt token related api logut er jonno
        app.post('/logout', (req, res) => {
            res.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production" ? true : false,
                sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            });

            res.send({ message: 'Logged out successfully' });
        });


        //part:2 addPost a chek korar jonno je 5ta er besi post korse kina user
        app.get('/posts/count/:email', verifyToken, async (req, res) => {
            try {
                const email = req.params.email;

                if (email !== req.decoded.email) {
                    return res.status(403).send({ message: 'forbidden access' })
                }

                const count = await postsCollection.countDocuments({ authorEmail: email });
                res.send({ postCount: count });
            } catch (error) {
                console.error('Error getting post count:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        //single user get korar api
        app.get('/users/:email', verifyToken, async (req, res) => {
            try {
                const userEmail = req.params.email;
                const user = await usersCollection.findOne({ email: userEmail })
                if (!user) {
                    return res.status(404).send({ message: 'user not found' })
                }
                res.send(user)
            } catch (error) {
                console.log('user geting api error', error)
                res.status(500).send({ message: 'Failed to get user data' })
            }
        })

        // user er latest 3ta post pawar get api
        app.get('/user-posts', verifyToken, async (req, res) => {
            const email = req.query.email;

            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' })
            }

            try {
                if (!email) {
                    return res.status(400).send({ message: 'Email is required' });
                }

                const posts = await postsCollection
                    .find({ authorEmail: email })
                    .sort({ postTime: -1 })
                    .limit(3)
                    .toArray();

                res.send(posts);

            } catch (error) {
                console.error('Failed to fetch latest posts:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        // single user er latest sob post pawar get api
        app.get('/usersPosts', verifyToken, async (req, res) => {
            const email = req.query.email;

            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' })
            }

            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 5;
            const skip = (page - 1) * limit;

            try {
                if (!email) {
                    return res.status(400).send({ message: 'Email is required' });
                }

                const totalPost = await postsCollection.countDocuments({ authorEmail: email })

                const posts = await postsCollection
                    .find({ authorEmail: email })
                    .sort({ postTime: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({
                    posts,
                    totalPages: Math.ceil(totalPost / limit),
                    currentPage: page,
                });

            } catch (error) {
                console.error('Failed to fetch latest posts:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });


        app.get('/posts', async (req, res) => {
            const { page = 1, sort = 'newest', tag = '' } = req.query;

            const skip = (parseInt(page) - 1) * 12;

            let pipeline = [];

            // যদি tag থাকে তাহলে filter করতে হবে
            if (tag) {
                pipeline.push({
                    $match: {
                        tag: { $regex: new RegExp(tag, 'i') } // case-insensitive
                    }
                });
            }

            // sort logic
            if (sort === 'popularity') {
                pipeline.push(
                    {
                        $addFields: {
                            voteCount: { $subtract: ['$upVote', '$downVote'] },
                        },
                    },
                    {
                        $sort: { voteCount: -1 }
                    }
                );
            } else {
                pipeline.push({ $sort: { postTime: -1 } }); // newest first
            }

            // pagination
            pipeline.push({ $skip: skip }, { $limit: 12 });

            // fetch posts
            let posts = await postsCollection.aggregate(pipeline).toArray();

            // every post er comment count
            const postIds = posts.map(post => post._id.toString());
            const commentsCount = await commentCollection.aggregate([
                { $match: { postId: { $in: postIds } } },
                {
                    $group: {
                        _id: "$postId",
                        totalComments: { $sum: 1 }
                    }
                }
            ]).toArray();

            // posts array তে comment count যোগ করা
            posts = posts.map(post => {
                const commentData = commentsCount.find(c => c._id === post._id.toString());
                return {
                    ...post,
                    totalComments: commentData ? commentData.totalComments : 0
                };
            });

            // count matching total posts for pagination
            const countQuery = tag
                ? { tag: { $regex: new RegExp(tag, 'i') } }
                : {};
            const total = await postsCollection.countDocuments(countQuery);

            res.send({ posts, total });
        });

        // latest post
        app.get('/latest', async (req, res) => {
            try {
                const latestPosts = await postsCollection
                    .find({})
                    .sort({ _id: -1 })
                    .limit(8)
                    .toArray();

                res.send(latestPosts)
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch latest posts' });
            }
        });

        // top voted post
        app.get('/top-voted', async (req, res) => {
            try {
                const topVotedPosts = await postsCollection
                    .find({})
                    .sort({ upVote: -1 })
                    .limit(8)
                    .toArray();

                res.send(topVotedPosts);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: 'Failed to fetch top voted posts' });
            }
        });


        // single post get api
        app.get('/post/:postId', async (req, res) => {
            const { postId } = req.params;
            try {
                const post = await postsCollection.findOne({ _id: new ObjectId(postId) })
                if (!post) {
                    return res.status(404).send({ message: 'post not found' })
                }
                res.send(post)
            } catch (error) {
                console.log('error fetching post', error)
                res.status(500).send({ message: 'Enternal Server Error' })
            }
        })


        // GET comments by postId
        app.get('/comments/:postId', async (req, res) => {
            const postId = req.params.postId;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 5;
            const skip = (page - 1) * limit;

            try {
                const totalComments = await commentCollection.countDocuments({ postId })
                const comments = await commentCollection.find({ postId })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({ comments, totalPages: Math.ceil(totalComments / limit) });
            } catch (error) {
                res.status(500).send({ error: 'Failed to fetch comments' });
            }
        });

        // all user er get api
        app.get('/all-users', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 5;
                const skip = (page - 1) * limit;

                const search = req.query.search || '';
                const query = search ? { name: { $regex: search, $options: 'i' } } : {};

                const totalUsers = await usersCollection.countDocuments(query);


                const result = await usersCollection.find(query)
                    .skip(skip)
                    .limit(limit)
                    .toArray();
                res.send({ result, totalPage: (Math.ceil(totalUsers / limit)) });
            } catch (error) {
                res.status(500).send({ message: 'User fetch failed' });
            }
        });

        // all announcements get api
        app.get("/announcements", async (req, res) => {
            try {
                const announcements = await announcementCollection
                    .find()
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(announcements);
            } catch (error) {
                console.error("Error fetching announcements:", error);
                res.status(500).send({ message: "Failed to fetch announcements" });
            }
        });

        // announcement count api
        app.get('/announcement-count', async (req, res) => {
            try {
                const count = await announcementCollection.estimatedDocumentCount();
                res.send({ count });
            } catch (error) {
                console.error("Failed to count announcements:", error);
                res.status(500).send({ error: "Failed to count announcements" });
            }
        });


        // Get all reported comments
        app.get('/reported-comments', verifyToken, verifyAdmin, async (req, res) => {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 5;
            const skip = (page - 1) * limit;
            try {
                const totalReports = await reportCollection.countDocuments();
                const reports = await reportCollection.
                    find()
                    .sort({ reportedAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({
                    reports,
                    totalPages: Math.ceil(totalReports / limit),
                    currentPage: page
                });
            } catch (error) {
                console.error('Error fetching reports:', error);
                res.status(500).send({ error: 'Failed to fetch reports' });
            }
        });


        // server.js or routes file
        app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const totalPosts = await postsCollection.estimatedDocumentCount();
                const totalComments = await commentCollection.estimatedDocumentCount();
                const totalUsers = await usersCollection.estimatedDocumentCount();

                res.json({ totalPosts, totalComments, totalUsers });
            } catch (err) {
                res.status(500).json({ message: "Failed to get stats" });
            }
        });

        // server.js or routes file
        app.get("/overView-stats", verifyToken, async (req, res) => {
            try {
                const totalPosts = await postsCollection.estimatedDocumentCount();
                const totalComments = await commentCollection.estimatedDocumentCount();
                const totalUsers = await usersCollection.estimatedDocumentCount();

                res.json({ totalPosts, totalComments, totalUsers });
            } catch (err) {
                res.status(500).json({ message: "Failed to get stats" });
            }
        });

        // get all tag
        app.get('/tags', async (req, res) => {
            try {
                const tags = await tagCollection.find().toArray();
                res.send(tags)
            } catch (error) {
                res.status(500).send({ message: 'failed to get tags' })
            }
        })

        // user role check korar get api 
        app.get('/users/:email/role', verifyToken, async (req, res) => {
            const email = req.params.email;
            try {
                const user = await usersCollection.findOne({ email: email });

                if (!user) {
                    return res.status(404).json({ message: 'User not found', role: 'user' });
                }

                res.json({ role: user.role || 'user' });
            } catch (error) {
                console.error('Error getting user role:', error);
                res.status(500).json({ message: 'Internal server error' });
            }
        });

        // user akta single post er kon kon comment report korse tar get api
        app.get('/comment/reports/:postId/:userEmail', verifyToken, async (req, res) => {
            const { postId, userEmail } = req.params;

            try {
                const reports = await reportCollection
                    .find({
                        reportedBy: userEmail,
                        postId: postId,
                    })
                    .toArray();

                // শুধু এই পোস্টের কমেন্টগুলোর রিপোর্ট ফিল্টার করো
                const commentIds = reports.map(report => report.commentId);
                res.send(commentIds);
            } catch (error) {
                res.status(500).send({ message: "Failed to fetch reported comments" });
            }
        });



        // user reports save mongodb 
        app.post('/comment/reports', verifyToken, async (req, res) => {
            try {
                const { commentId, reportedBy, feedback, commentText, postId } = req.body;

                // Basic validation
                if (!commentId || !reportedBy || !feedback || !commentText) {
                    return res.status(400).json({ message: 'All fields are required' });
                }

                //Check if this user already reported this comment
                const existingReport = await reportCollection.findOne({
                    commentId,
                    reportedBy,
                });

                if (existingReport) {
                    return res.status(409).json({ message: 'You already reported this comment' });
                }

                const reportDoc = {
                    commentId,
                    commentText,
                    postId,
                    reportedBy,
                    feedback,
                    reportedAt: new Date(),
                };

                const result = await reportCollection.insertOne(reportDoc);

                res.status(201).json({ message: 'Report submitted successfully', reportId: result.insertedId });
            } catch (error) {
                console.error('Error inserting report:', error);
                res.status(500).json({ message: 'Internal server error' });
            }
        });



        //Part:1 register howar por userInfo database te insart kora
        app.post('/users', async (req, res) => {
            try {
                const user = req.body;
                // Check if user already exists by email
                const existing = await usersCollection.findOne({ email: user.email });
                if (existing) {
                    return res.status(204).send();
                }
                const result = await usersCollection.insertOne(user);
                res.send(result);
            } catch (error) {
                console.error('Error inserting user:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        //part:2 addPost er data database a pathanor jonno
        app.post('/posts', verifyToken, async (req, res) => {
            try {
                const post = req.body;
                const result = await postsCollection.insertOne(post);
                res.send(result);
            } catch (error) {
                console.error('Error inserting post:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });



        //stripe payment method
        app.post('/create-payment-intent', async (req, res) => {
            try {
                const { amountInCents } = req.body;
                if (!amountInCents) return res.status(400).send({ message: "Amount is required" });

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amountInCents,
                    currency: 'usd',
                    payment_method_types: ['card'],
                });

                res.send({
                    clientSecret: paymentIntent.client_secret,
                });
            } catch (error) {
                console.error(error);
                res.status(500).send({ error: error.message });
            }
        });

        // post er comment save kora
        app.post('/comments', verifyToken, async (req, res) => {
            try {
                const comment = req.body;
                const result = await commentCollection.insertOne(comment);
                res.send(result);
            } catch (error) {
                console.error("Error posting comment:", error.message);
                res.status(500).send({ error: "Failed to post comment" });
            }
        });

        // announcement save in the database
        app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const announcement = req.body;
                const result = await announcementCollection.insertOne(announcement);
                res.send(result);
            } catch (error) {
                console.error("Error adding announcement:", error);
                res.status(500).send({ message: "Failed to add announcement." });
            }
        });


        // Add new tag with trim & duplicate check
        app.post("/tag", verifyToken, verifyAdmin, async (req, res) => {
            let { tag } = req.body;

            // Trim tag name
            tag = tag?.trim();

            // Check empty after trimming
            if (!tag) {
                return res.status(400).send({ message: "Tag name is required" });
            }

            try {
                // Duplicate check (case-insensitive)
                const existingTag = await tagCollection.findOne({ tag: { $regex: new RegExp(`^${tag}$`, 'i') } });

                if (existingTag) {
                    return res.status(409).send({ message: "Tag already exists" });
                }

                // Insert new tag
                const result = await tagCollection.insertOne({ tag });
                res.send({ insertedId: result.insertedId });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Failed to add tag" });
            }
        });



        // Update user membership status
        app.patch('/users/member/:email', async (req, res) => {
            try {
                const email = req.params.email;
                const filter = { email: email };
                const updateDoc = {
                    $set: {
                        badges: ['gold'],
                        isMember: true,
                        role: 'member'
                    }
                };

                const result = await usersCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                console.error('Error updating membership:', error);
                res.status(500).send({ message: 'Failed to update membership' });
            }
        });

        // update api upvote and downvote
        app.patch('/post/upvote/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const result = await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $inc: { upVote: 1 } }
                );
                res.send(result)

            } catch (error) {
                console.log('upvote error', error)
                res.status(500).send({ message: 'upvote faild' })
            }
        })

        app.patch('/post/downvote/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const result = await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $inc: { downVote: 1 } }
                )
                res.send(result)
            } catch (error) {
                console.log('downvote error', error)
                res.status(500).send({ message: 'downvote faild' })
            }
        })

        //Admin বানানোর রুট
        app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
            const userId = req.params.id;

            try {
                const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

                const filter = { _id: new ObjectId(userId) };
                const updateDoc = {
                    $set: {
                        role: 'admin',
                        previousRole: user?.role || 'user' // আগের রোল সংরক্ষণ
                    }
                };

                const result = await usersCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                console.error('Error making user admin:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });

        // Remove Admin a click korle → আগের রোলে ফেরত পাঠানোর রুট verifyAdmin
        app.patch('/users/remove-admin/:id', verifyToken, verifyAdmin, async (req, res) => {
            const userId = req.params.id;

            try {
                const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(userId) },
                    {
                        $set: { role: user.previousRole || 'user' },
                        $unset: { previousRole: "" }
                    }
                );

                res.send(result);
            } catch (error) {
                console.error('Error removing admin:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });


        // delete ownUser post and relevent comment
        app.delete('/user-posts/:id', verifyToken, async (req, res) => {
            const postId = req.params.id;

            try {
                // Step 1: Delete the post
                const postResult = await postsCollection.deleteOne({ _id: new ObjectId(postId) });

                // Step 2: Delete all comments related to that post
                const commentResult = await commentCollection.deleteMany({ postId: postId });

                res.send({
                    postDeleted: postResult.deletedCount,
                    commentsDeleted: commentResult.deletedCount,
                    message: 'Post and related comments deleted successfully'
                });
            } catch (error) {
                console.error('Error deleting post/comments:', error);
                res.status(500).json({ message: 'Internal Server Error' });
            }
        });

        // activities page a comment delete api and  reports delete api
        app.delete('/admin/delete-reported-comment/:reportId/:commentId', verifyToken, verifyAdmin, async (req, res) => {
            const { reportId, commentId } = req.params;

            try {
                // Delete the comment
                const deleteComment = await commentCollection.deleteOne({ _id: new ObjectId(commentId) });

                // Delete the report
                const deleteReport = await reportCollection.deleteOne({ _id: new ObjectId(reportId) });

                res.send({
                    success: true,
                    deletedComment: deleteComment.deletedCount,
                    deletedReport: deleteReport.deletedCount,
                });

            } catch (err) {
                console.error(err);
                res.status(500).send({ success: false, error: "Failed to delete" });
            }
        });




        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
