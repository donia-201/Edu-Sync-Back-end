from flask import Blueprint, request, jsonify
from firebase_admin import firestore
from datetime import datetime

from utils.firebase_config import db
from utils.auth import require_auth

notes_bp = Blueprint('notes', __name__, url_prefix='/api/notes')

@notes_bp.route('', methods=['GET'])
@require_auth
def get_notes():
    """الحصول على جميع الملاحظات الخاصة بالمستخدم الحالي"""
    try:
        user_id = request.user_data['user_id']
        notes_ref = db.collection('users').document(user_id).collection('notes')
        
        notes_docs = notes_ref.order_by('createdAt', direction=firestore.Query.DESCENDING).stream()
        
        notes_list = []
        for note_doc in notes_docs:
            note_data = note_doc.to_dict()
            note_data['id'] = note_doc.id
            notes_list.append(note_data)
        
        return jsonify({'notes': notes_list, 'success': True})
    except Exception as e:
        print(f"Error fetching notes: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to fetch notes', 'success': False}), 500


@notes_bp.route('', methods=['POST'])
@require_auth
def create_note():
    """إنشاء ملاحظة جديدة"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        note_data = {
            'type': data.get('type', 'note'),
            'content': data.get('content', ''),
            'color': data.get('color', '#ffffff'),
            'checked': data.get('checked', False),
            'createdAt': data.get('createdAt', datetime.utcnow().isoformat()),
            'updatedAt': datetime.utcnow().isoformat()
        }
        
        notes_ref = db.collection('users').document(user_id).collection('notes')
        
        if 'id' in data:
            note_ref = notes_ref.document(data['id'])
            note_ref.set(note_data)
            note_id = data['id']
        else:
            doc_ref = notes_ref.add(note_data)
            note_id = doc_ref[1].id
        
        note_data['id'] = note_id
        
        return jsonify({'note': note_data, 'success': True}), 201
    except Exception as e:
        print(f"Error creating note: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to create note', 'success': False}), 500


@notes_bp.route('/<note_id>', methods=['PUT'])
@require_auth
def update_note(note_id):
    """تحديث ملاحظة موجودة"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        print(f"Update received for Note ID: {note_id}, Data: {data}")

        update_data = {
            'updatedAt': datetime.utcnow().isoformat()
        }
        
        allowed_fields = ['content', 'color', 'checked', 'type']
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        note_ref = db.collection('users').document(user_id).collection('notes').document(note_id)
        
        if not note_ref.get().exists:
            return jsonify({'error': 'Note not found', 'success': False}), 404
        
        note_ref.update(update_data)
        
        print(f"✅ Note {note_id} updated successfully") 

        updated_note = note_ref.get().to_dict()
        updated_note['id'] = note_id
        
        return jsonify({'note': updated_note, 'success': True})
    except Exception as e:
        print(f"Error updating note: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to update note', 'success': False}), 500


@notes_bp.route('/<note_id>', methods=['DELETE'])
@require_auth
def delete_note(note_id):
    """حذف ملاحظة - ✨ NEW ROUTE"""
    try:
        user_id = request.user_data['user_id']
        
        note_ref = db.collection('users').document(user_id).collection('notes').document(note_id)
        
        if not note_ref.get().exists:
            return jsonify({'error': 'Note not found', 'success': False}), 404
        
        note_ref.delete()
        
        print(f"✅ Note {note_id} deleted successfully")
        
        return jsonify({'message': 'Note deleted successfully', 'success': True})
    except Exception as e:
        print(f"Error deleting note: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to delete note', 'success': False}), 500


@notes_bp.route('/reorder', methods=['POST'])
@require_auth
def reorder_notes():
    """تحديث ترتيب الملاحظات"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data or 'order' not in data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        order = data['order']
        
        batch = db.batch()
        for index, note_id in enumerate(order):
            note_ref = db.collection('users').document(user_id).collection('notes').document(note_id)
            batch.update(note_ref, {
                'order': index, 
                'updatedAt': datetime.utcnow().isoformat()
            })
        
        batch.commit()
        
        return jsonify({'message': 'Order updated successfully', 'success': True})
    except Exception as e:
        print(f"Error reordering notes: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to reorder notes', 'success': False}), 500