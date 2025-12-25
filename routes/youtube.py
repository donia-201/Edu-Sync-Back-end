from flask import Blueprint, request, jsonify
import requests
from config import YOUTUBE_API_KEY

youtube_bp = Blueprint('youtube', __name__)

def is_educational_content(video_item):
    """فلترة خفيفة جداً: فقط يمنع المحتوى الترفيهي الواضح"""
    snippet = video_item.get("snippet", {})
    title = snippet.get("title", "").lower()
    description = snippet.get("description", "").lower()
    
    banned_keywords = [
        # ألعاب
        "gameplay", "let's play", "gaming channel", "game walkthrough", "fortnite", 
        "minecraft", "pubg", "call of duty", "fifa", "ps5", "xbox",
        
        # موسيقى
        "official music video", "official video", "music video", "مهرجان", "كليب",
        "dance cover", "choreography", "اغنية", "اغاني",
        
        # ترفيه
        "prank", "funny moments", "comedy sketch", "stand up comedy",
        "reaction video", "تحدي", "برانك", "مقلب",
        
        # أفلام ومسلسلات
        "trailer", "full movie", "episode", "مسلسل", "فيلم"
    ]
    
    text_to_check = title + " " + description
    for banned in banned_keywords:
        if banned in text_to_check:
            return False
    
    return True

@youtube_bp.get("/youtube-search")
def youtube_search():
    """بحث YouTube مع فلترة خفيفة جداً"""
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")
        
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        if not YOUTUBE_API_KEY:
            return jsonify({
                "error": "YouTube API key not configured",
                "hint": "Add API_KEY to environment variables",
                "display_message": "YouTube API is not exist"
            }), 500

        api_max_results = str(min(int(max_results) * 3, 50))
        
        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": api_max_results,
            "q": q,
            "order": "relevance",
            "videoEmbeddable": "true",
            "safeSearch": "moderate",
            "key": YOUTUBE_API_KEY
        }

        print(f"🔍 Searching YouTube: '{q}' (requesting: {api_max_results})")
        
        r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=15)
        
        if not r.ok:
            try:
                err = r.json()
                error_msg = err.get('error', {}).get('message', 'Unknown error')
            except:
                err = {"text": r.text}
                error_msg = f"HTTP {r.status_code}"
            
            print(f" YouTube API Error {r.status_code}:", err)
            
            return jsonify({
                "error": "YouTube API error",
                "status": r.status_code,
                "details": err,
                "display_message": f"error in YouTube API: {error_msg}"
            }), 502

        data = r.json()
        all_items = data.get("items", [])
        
        print(f" YouTube returned {len(all_items)} results")
        
        if not all_items:
            return jsonify({
                "items": [],
                "total": 0,
                "display_message": f"No videos match with '{q}', try another words"
            })
        
        filtered_items = [item for item in all_items if is_educational_content(item)]
        
        final_items = filtered_items[:int(max_results)]
        
        print(f"✅ After filtering: {len(final_items)} videos")
        print(f"🚫 Filtered out: {len(all_items) - len(filtered_items)} entertainment videos")
        
        if not final_items:
            return jsonify({
                "items": [],
                "total": 0,
                "display_message": f"Couldn't find any educational content matching '{q}', try words like 'tutorial' or 'course'."
            })

        return jsonify({
            "items": final_items,
            "total": len(final_items),
            "original_total": len(all_items),
            "filtered_count": len(all_items) - len(filtered_items),
            "display_message": f"We found {len(final_items)} video(s)"
        })

    except requests.exceptions.Timeout:
        print("⏱ YouTube API timeout")
        return jsonify({
            "error": "YouTube API timeout",
            "display_message": "Request timeout. Please try again."
        }), 504
    except requests.exceptions.RequestException as e:
        print(f" Network error: {str(e)}")
        return jsonify({
            "error": "Network error",
            "details": str(e),
            "display_message": "Network error. Check your connection."
        }), 503
    except Exception as e:
        print(f" youtube_search error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Server error: {str(e)}",
            "display_message": "Server error. Please try again later."
        }), 500