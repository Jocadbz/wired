// Initialize sessionToken from cookie and currentUser from localStorage
let sessionToken = getCookie('session_token');
let currentUser = localStorage.getItem('currentUser') || null;

// Function to get cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// Function to load posts
function loadPosts(sort = 'date') {
    fetch(`https://wired.jocadbz.xyz/posts?sort=${sort}`, {
        headers: { 'X-Session-Token': sessionToken || '' }
    })
        .then(response => {
            if (!response.ok) throw new Error('Error loading posts');
            return response.json();
        })
        .then(posts => {
            const list = document.getElementById('posts-list');
            if (!list) return;
            list.innerHTML = '';
            posts.forEach(post => {
                const li = document.createElement('li');
                li.className = 'post' + (post.pinned ? ' pinned' : '');
                li.innerHTML = `
                    ${post.pinned ? '<span>📌 [Pinned]</span> ' : ''}
                    <button class="upvote-btn" onclick="upvote(${post.id})" ${!sessionToken ? 'disabled' : ''}>▲</button>
                    ${post.url ? `<a href="${post.url}" target="_blank">${post.pinned ? '[PINNED] ' + post.title : post.title}</a>` : `<span>${post.pinned ? '[PINNED] ' + post.title : post.title}</span>`} (${post.votes} votes)
                    <p>${post.description}</p>
                    ${post.imageUrl ? `<img src="${post.imageUrl}" alt="Post image">` : ''}
                    <p>By: ${post.author}${currentUser === 'admin' && post.authorIP ? ' (IP: ' + post.authorIP + ')' : ''} | <a href="comments.html?postId=${post.id}">Comments (${(post.comments || []).length + (post.replies || []).length})</a></p>
                    ${(currentUser === post.author || currentUser === 'admin') ? `
                        <button class="delete-btn" onclick="deletePost(${post.id})">Delete</button>
                    ` : ''}
                    ${currentUser === 'admin' ? `
                        ${post.pinned ? `
                            <button class="unpin-btn" onclick="unpinPost(${post.id})">Unpin</button>
                        ` : `
                            <button class="pin-btn" onclick="pinPost(${post.id})">Pin</button>
                        `}
                    ` : ''}
                `;
                list.appendChild(li);
            });
        })
        .catch(err => alert(err.message));
    updateUI();
}

// Function to submit a new post
function submitPost(e) {
    e.preventDefault();
    if (!sessionToken) {
        alert("You need to be logged in to create a post");
        return;
    }
    const title = document.getElementById('title').value;
    const url = document.getElementById('url').value || '';
    const description = document.getElementById('description').value;
    const imageUrl = document.getElementById('imageUrl').value || '';

    fetch('https://wired.jocadbz.xyz/posts', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json', 
            'X-Session-Token': sessionToken
        },
        body: JSON.stringify({ title, url, description, imageUrl })
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(newPost => {
            document.getElementById('post-form').reset();
            loadPosts();
        })
        .catch(err => alert(err.message));
}

// Function to upvote
function upvote(postId) {
    if (!sessionToken) {
        alert("You need to be logged in to vote");
        return;
    }

    fetch(`https://wired.jocadbz.xyz/posts/${postId}/upvote`, {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(() => loadPosts())
        .catch(err => alert(err.message));
}

// Function to delete post
function deletePost(postId) {
    fetch(`https://wired.jocadbz.xyz/posts/${postId}`, {
        method: 'DELETE',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            alert(message);
            loadPosts();
        })
        .catch(err => alert(err.message));
}

// Function to pin post
function pinPost(postId) {
    fetch(`https://wired.jocadbz.xyz/posts/${postId}/pin`, {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(() => loadPosts())
        .catch(err => alert(err.message));
}

// Function to unpin post
function unpinPost(postId) {
    fetch(`https://wired.jocadbz.xyz/posts/${postId}/unpin`, {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(() => loadPosts())
        .catch(err => alert(err.message));
}

// Function to register user
function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('https://wired.jocadbz.xyz/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            sessionToken = getCookie('session_token');
            currentUser = username;
            localStorage.setItem('currentUser', username);
            alert(message);
            loadPosts();
        })
        .catch(err => alert(err.message));
}

// Function to login
function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('https://wired.jocadbz.xyz/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            sessionToken = getCookie('session_token');
            currentUser = username;
            localStorage.setItem('currentUser', username);
            alert(message);
            loadPosts();
            loadComments();
        })
        .catch(err => alert(err.message));
}

// Function to logout
function logout() {
    fetch('https://wired.jocadbz.xyz/logout', {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => response.text())
        .then(message => {
            sessionToken = null;
            currentUser = null;
            localStorage.removeItem('currentUser');
            alert(message);
            loadPosts();
            loadComments();
        });
}

// Function to ban user
function banUser() {
    const targetUser = document.getElementById('ban-username').value;
    fetch(`https://wired.jocadbz.xyz/ban/user/${targetUser}`, {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            alert(message);
            loadPosts();
        })
        .catch(err => alert(err.message));
}

// Function to ban IP
function banIP() {
    const ip = document.getElementById('ban-ip').value;
    fetch(`https://wired.jocadbz.xyz/ban/ip/${ip}`, {
        method: 'POST',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            alert(message);
            loadPosts();
        })
        .catch(err => alert(err.message));
}

// Function to load comments and replies
function loadComments() {
    const urlParams = new URLSearchParams(window.location.search);
    const postId = urlParams.get('postId');
    if (!postId) return;

    fetch(`https://wired.jocadbz.xyz/posts`, {
        headers: { 'X-Session-Token': sessionToken || '' }
    })
        .then(response => response.json())
        .then(posts => {
            const post = posts.find(p => p.id == postId);
            if (!post) {
                alert("Post not found");
                return;
            }

            document.getElementById('post-title').textContent = post.pinned ? '[PINNED] ' + post.title : post.title;
            document.getElementById('post-url').innerHTML = post.url ? `<a href="${post.url}" target="_blank">${post.url}</a>` : '';
            document.getElementById('post-description').textContent = post.description;
            const imgElement = document.getElementById('post-image');
            if (post.imageUrl) {
                imgElement.src = post.imageUrl;
                imgElement.style.display = 'block';
            } else {
                imgElement.style.display = 'none';
            }

            const list = document.getElementById('comments-list');
            list.innerHTML = '';
            post.comments.forEach(comment => {
                const div = document.createElement('div');
                div.className = 'comment';
                let repliesHTML = '';
                const replies = (post.replies || []).filter(r => r.commentId === comment.id);
                if (replies.length > 0) {
                    repliesHTML = '<div class="replies">';
                    replies.forEach(reply => {
                        repliesHTML += `
                            <div class="reply">
                                <p>${reply.text} (By: ${reply.author})</p>
                                ${currentUser === 'admin' ? `<button class="delete-btn" onclick="deleteReply(${post.id}, ${reply.id})">Delete</button>` : ''}
                            </div>
                        `;
                    });
                    repliesHTML += '</div>';
                }
                div.innerHTML = `
                    <p>${comment.text} (By: ${comment.author})</p>
                    ${repliesHTML}
                    ${sessionToken ? `<button class="reply-btn" onclick="showReplyForm(${post.id}, ${comment.id})">Reply</button>` : ''}
                    ${currentUser === 'admin' ? `<button class="delete-btn" onclick="deleteComment(${post.id}, ${comment.id})">Delete</button>` : ''}
                `;
                list.appendChild(div);
            });

            if (sessionToken) {
                document.getElementById('comment-form').style.display = 'block';
            } else {
                document.getElementById('comment-form').style.display = 'none';
            }
        });
}

// Function to show reply form
function showReplyForm(postId, commentId) {
    const existingForm = document.getElementById(`reply-form-${commentId}`);
    if (existingForm) {
        existingForm.remove();
        return;
    }

    const commentDiv = event.target.parentElement;
    const form = document.createElement('form');
    form.id = `reply-form-${commentId}`;
    form.className = 'reply-form';
    form.innerHTML = `
        <textarea id="reply-text-${commentId}" placeholder="Your reply..."></textarea>
        <button type="submit">Submit Reply</button>
    `;
    form.addEventListener('submit', (e) => submitReply(e, postId, commentId));
    commentDiv.appendChild(form);
}

// Function to submit comment or reply
function submitComment(e) {
    e.preventDefault();
    if (!sessionToken) {
        alert("You need to be logged in to comment");
        return;
    }

    const urlParams = new URLSearchParams(window.location.search);
    const postId = urlParams.get('postId');
    const text = document.getElementById('comment-text').value;

    fetch(`https://wired.jocadbz.xyz/posts/${postId}/comments`, {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json', 
            'X-Session-Token': sessionToken
        },
        body: JSON.stringify({ text })
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(() => {
            document.getElementById('comment-text').value = '';
            loadComments();
        })
        .catch(err => alert(err.message));
}

// Function to submit reply
function submitReply(e, postId, commentId) {
    e.preventDefault();
    if (!sessionToken) {
        alert("You need to be logged in to reply");
        return;
    }

    const text = document.getElementById(`reply-text-${commentId}`).value;

    fetch(`https://wired.jocadbz.xyz/posts/${postId}/comments`, {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json', 
            'X-Session-Token': sessionToken
        },
        body: JSON.stringify({ text, commentId })
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error); });
            }
            return response.json();
        })
        .then(() => {
            document.getElementById(`reply-form-${commentId}`).remove();
            loadComments();
        })
        .catch(err => alert(err.message));
}

// Function to delete comment
function deleteComment(postId, commentId) {
    fetch(`https://wired.jocadbz.xyz/posts/${postId}/comments/${commentId}`, {
        method: 'DELETE',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            alert(message);
            loadComments();
        })
        .catch(err => alert(err.message));
}

// Function to delete reply
function deleteReply(postId, replyId) {
    fetch(`https://wired.jocadbz.xyz/posts/${postId}/replies/${replyId}`, {
        method: 'DELETE',
        headers: { 
            'X-Session-Token': sessionToken
        }
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.text();
        })
        .then(message => {
            alert(message);
            loadComments();
        })
        .catch(err => alert(err.message));
}

// Update UI based on login status
function updateUI() {
    document.getElementById('logout-btn').style.display = sessionToken ? 'inline' : 'none';
    document.getElementById('admin-tools').style.display = currentUser === 'admin' ? 'block' : 'none';
}

// Bind events
if (document.getElementById('post-form')) {
    document.getElementById('post-form').addEventListener('submit', submitPost);
}
if (document.getElementById('comment-form')) {
    document.getElementById('comment-form').addEventListener('submit', submitComment);
}

// Load posts or comments on page load
if (window.location.pathname.includes('comments.html')) {
    loadComments();
} else {
    loadPosts();
}